# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# qpkg.inc
#
# $Revision: 1.28 $
#

include('global_settings.inc');

global_var qpkg_list, qpkg_report, qpkg_tests;
qpkg_report = '';
qpkg_tests = make_list();

function get_ver_type(typ)
{
 debug_print(level: 4, 'typ=', typ);
 if (typ =~ '^20[01][0-9]\\.(0[1-9]|1[12])\\.([0-2][0-9]|3[01])' ||
     typ =~ '^20[01][0-9](0[1-9]|1[12])([0-2][0-9]|3[01])') return 1;
 if (typ =~ '^alpha') return 2;
 if (typ =~ '^beta') return 3;
 if (typ =~ '^pre') return 4;
 if (typ =~ '^rc') return 5;
 if (typ =~ '^p[0-9]') return 6;
 if (typ == '') return 7;
 debug_print('get_ver_type: typ=', typ, ' is not recognized\n');
 return NULL;
}

# Retuns 1 if surely matches, -1 if surely does not match, NULL or 0 otherwise
function qpkg_ver_cmp(ver, ref, op)
{
  local_var	inf, sup, eq;
  local_var	r, v, i, n, nr, nv;
  local_var     ref_base, ref_r, ver_base, ver_r;
  local_var     vab, vabN, vN, rab, rabN, rN; 
  local_var	v_type, r_type;
  local_var     v_pre, v_rc;
  local_var 	flag, ver2, ref2;

  debug_print(level: 3, 'qpkg_ver_cmp: ver=', ver, ' ref=', ref, ' op=', op, '\n');

  # Easy cases: identity
  if (op == 'eq')
   if (ver == ref) return 1; else return -1;
  if (ver == ref)
    if ('e' >< op) return 1; else return -1;

  if ('l' >< op) { inf = 1; sup = -1; } else { inf = -1; sup = 1; }
  if ('e' >< op) { eq = 1; } else { eq = -1; }

  # -r0 treatement
  v = eregmatch(string: ref, icase: 0, pattern: '^(.+)-r([0-9]+)+$');
  if (isnull(v)) { ref_base = ref; ref_r = 0; }
  else { ref_base = v[1]; ref_r = int(v[2]); }

  v = eregmatch(string: ver, icase: 0, pattern: '^(.+)-r([0-9]+)$');
  if (isnull(v)) { ver_base = ver; ver_r = 0; }
  else { ver_base = v[1]; ver_r = int(v[2]); }

  if (ver_base == ref_base)
    if  (ver_r < ref_r) return inf;
    else if (ver_r == ref_r) return eq;
    else return sup;
  # We have remove -r* at the end of the strings

  v = eregmatch(string: ver, pattern: '^([^_]+)_([^_]+)$');
  if (isnull(v))
   v = eregmatch(string: ver, pattern: '^([^_]+)\\.(20[0-9][0-9][01][0-9][0-3][0-9])$');
  if (! isnull(v))
  {
   r = eregmatch(string: ref, pattern: '^([^_]+)_([^_]+)$');
   if (isnull(r))
    r = eregmatch(string: ref, pattern: '^([^_]+)\\.(20[0-9][0-9][01][0-9][0-3][0-9])$');
   if (! isnull(r) && v[1] == r[1])
   {
    debug_print(level: 2, 'qpkg_ver_cmp: same major & miror ', v[1], ' - comparing v=', v[2], ' with r=', r[2]);
    v_type = get_ver_type(typ: v[2]);
    r_type = get_ver_type(typ: r[2]);
    if (v_type && r_type)
     if (v_type < r_type) return inf;
     else if (v_type > r_type) return sup;
   }
  }

  # alpha / beta
  v = eregmatch(string: ver_base, icase: 0, pattern: '^(.+)_(alpha|beta)([0-9]+)$');
  r = eregmatch(string: ref_base, icase: 0, pattern: '^(.+)_(alpha|beta)([0-9]+)$');
  if (! isnull(v)) { ver_base = v[1]; vab = v[2]; vabN = int(v[3]); }
  if (! isnull(r)) { ref_base = r[1]; rab = r[2]; rabN = int(r[3]); }
  if (ver_base == ref_base)
  {
    # I supose that 1.30 is newer than 1.30_alpha3
    if (! vab) vab = 'zzzz';
    if (! rab) rab = 'zzzz';
    if (vab < rab) return inf;
    else if (vab > rab) return sup;
    if (vabN < rabN) return inf;
    else if (vabN > rabN) return sup;
  }
  # _alpha* has been removed

  debug_print(level: 3, 'qpkg_ver_cmp: After _alpha/beta, ver_base=', ver_base, ' ref_base=', ref_base);

  # _p*
  v = eregmatch(string: ver_base, icase: 0, pattern: '^(.+)_p([0-9]+)$');
  r = eregmatch(string: ref_base, icase: 0, pattern: '^(.+)_p([0-9]+)$');
  vN = NULL; rN = NULL;
  if (! isnull(v)) { ver_base = v[1]; vN = int(v[2]); }
  if (! isnull(r)) { ref_base = r[1]; rN = int(r[2]); }
  if (ver_base == ref_base)
  {
    # 1.30_p2 is newer than 1.30
    if (vN < rN) return inf;
    else if (vN > rN) return sup;
  }

  debug_print(level: 3, 'qpkg_ver_cmp: After _p, ver_base=', ver_base, ' ref_base=', ref_base);

  # _rc*
  v = eregmatch(string: ver_base, icase: 0, pattern: '^(.+)_rc([0-9]+)$');
  r = eregmatch(string: ref_base, icase: 0, pattern: '^(.+)_rc([0-9]+)$');
  vN = NULL; rN = NULL;
  if (! isnull(v)) { ver_base = v[1]; vN = int(v[2]); v_rc = v; }
  if (! isnull(r)) { ref_base = r[1]; rN = int(r[2]); }
  if (ver_base == ref_base)
  {
    # 1.30_rc3 is older than 1.30
    if (! vN && rN) return sup;
    if (vN && ! rN) return inf;

    if (vN < rN) return inf;
    else if (vN > rN) return sup;
  }

  debug_print(level: 3, 'qpkg_ver_cmp: After _rc, ver_base=', ver_base, ' ref_base=', ref_base);

  # _pre*
  # The result will probably be wrong if we compare 1.30_pre1 and 1.30_pre20020319
  # but how are we supposed to solve such a case?
  v = eregmatch(string: ver_base, icase: 0, pattern: '^(.+)_pre([0-9]+)$');
  r = eregmatch(string: ref_base, icase: 0, pattern: '^(.+)_pre([0-9]+)$');
  vN = NULL; rN = NULL;
  if (! isnull(v)) { ver_base = v[1]; vN = int(v[2]); v_pre = v; }
  if (! isnull(r)) { ref_base = r[1]; rN = int(r[2]); }
  if (ver_base == ref_base)
  {
    # 1.30 is newer than 1.30_pre20020318
    if (! vN && rN) return sup;
    if (vN && ! rN) return inf;

    if (vN < rN) return inf;
    else if (vN > rN) return sup;
  }

  debug_print(level: 3, 'qpkg_ver_cmp: After _pre, ver_base=', ver_base, ' ref_base=', ref_base);

  # Date pre-version
  # Some package use something like 1.0.20070321
  # That's tricky:
  # media-video/mplayer-1.0_rc1_p20070824 > media-video/mplayer-1.0.20070622
  # but
  # net-print/foomatic-db-engine-3.0.2 < net-print/foomatic-db-engine-3.0.20060720
  v = eregmatch(string: ver_base, icase: 0, pattern: '^(.+)\\.(200[5-9](0[1-9]|1[0-2])([0-2][0-9]|3[01]))$');
  r = eregmatch(string: ref_base, icase: 0, pattern: '^(.+)\\.(200[5-9](0[1-9]|1[0-2])([0-2][0-9]|3[01]))$');
  debug_print(level: 3, 'qpkg_ver_cmp: date pre-version compares ver=', ver_base, ' with ref=', ref_base);
  
  vN = NULL; rN = NULL;
  flag = 0;
  if (! isnull(v)) { ver_base = v[1]; vN = int(v[2]); flag = 1;}
  else # TBD: implement something more robust!
  {
   v = eregmatch(string: ver_base, icase: 0, pattern: '^(.+)\\.([0-9]+)$');
   if (! isnull(v)) { ver2 = v[1]; vN = int(v[2]); }
  } 
  if (! isnull(r)) { ref_base = r[1]; rN = int(r[2]); flag = 1;}
  else
  {
   r = eregmatch(string: ref_base, icase: 0, pattern: '^(.+)\\.([0-9]+)$');
   if (! isnull(r)) { ref2 = r[1]; rN = int(r[2]); }
  }
  if (flag)
  if (ver_base == ref_base)
  {
    # 1.0.20070321 is older than 1.0
    if (! vN && rN) return sup;
    if (vN && ! rN) return inf;

    if (vN < rN) return inf;
    else if (vN > rN) return sup;
  }
  else if (ver_base == ref2)
  {
    # 1.0.20070321 maybe newer than 1.0.2?
    debug_print(level: 2, 'qpkg_ver_cmp: ver=', ver, ' may be newer than ref=', ref);
    return sup;
  }
  else if (ver2 == ref_base)
  {
    debug_print(level: 2, 'qpkg_ver_cmp: ver=', ver, ' may be older than ref=', ref);
    return inf;
  }

  debug_print(level: 3, 'qpkg_ver_cmp: After _200ymmdd, ver_base=', ver_base, ' ref_base=', ref_base);

  # Date
  # Some packages use something like "2004.10.1"
  # Change "2004.10.1" into "2004.10.01" 
  if (ref_base =~ "^((19|20)[0-9]{2})\.([0-9]{2})\.([0-9])$")
    ref_base = strcat(substr(ref_base, 0, 7), '0', substr(ref_base, 8));
  if (ver_base =~ "^((19|20)[0-9]{2})\.([0-9]{2})\.([0-9])$")
    ver_base = strcat(substr(ver_base, 0, 7), '0', substr(ver_base, 8));

  debug_print(level: 3, 'qpkg_ver_cmp: date parsing: ver_base=', ver_base, ' ref_base=', ref_base, '\n');

  if (op[0] != 'r') # special case for rge, rlt...
  if (ref_base =~ "^(19|20)[0-9]{2}\.?[0-9]{2}\.?[0-9]{2}$")
    if (ver_base !~ "^[12][90][0-9]{2}\.?[0-9]{2}\.?[0-9]{2}$")
    {
      debug_print('qpkg_ver_cmp: do not know how to compare a date to something else - ver_base=', ver_base, ' ref_base=', ref_base, '\n');
      return NULL;
    }
    else
    {
      ref_base = int(str_replace(string: ref_base, find: ".", replace: ""));
      ver_base = int(str_replace(string: ver_base, find: ".", replace: ""));
      debug_print(level: 3, 'Comparing dates: ver=', ver_base, ' ref=', ref_base, '\n');
      if (ver_base < ref_base) return inf;
      else if (ver_base > ref_base) return sup;
      else return eq;
    }

  debug_print(level: 3, 'qpkg_ver_cmp: After date parsing: ver_base=', ver_base, ' ref_base=', ref_base, '\n');

  # Simple number
  if (op[0] != 'r') # special case for rge, rlt...
  if (ver_base =~ '^[0-9]+$' && ref_base =~ '^[0-9]+$')
  {
    debug_print(level: 3, 'Comparing numbers: ver=', ver_base, ' ref=', ref_base, '\n');
    v = int(ver_base); r = int(ref_base);
    if (v < r) return inf;
    else if (v > r) return sup;
    else if (v == r) return eq;
  }

  # Clasic version number
  if (ver_base =~ "^[0-9.]+" && ref_base =~ "^[0-9.]+")
  {
    debug_print(level: 3, 'Comparing versions: ver=', ver_base, ' ref=', ref_base, '\n');
    v = split(ver_base, sep: '.', keep: 0);
    r = split(ref_base, sep: '.', keep: 0);
    nv = max_index(v); nr = max_index(r);
    if (nv < nr) n = nv; else n = nr;

    # special case for rge, rlt...
    if (op[0] == 'r' && v[0] != r[0]) return -1;

    for (i = 0; i < n; i ++)
    {
     local_var vv, rr;
     vv = v[i]; rr = r[i];
     debug_print(level: 4, 'Comparing versions: ', vv, ' & ', rr, '\n');
     # Special case: dev-perl/Convert-UUlib-1.051 < dev-perl/Convert-UUlib-1.09
     if (vv[0] == '0' || rr[0] == '0')
     {
       local_var	lv, lr;
       lv = strlen(vv); lr = strlen(rr);
       if (lv > lr) rr += crap(data: '0', length: lv - lr);
       else if (lr > lv) vv += crap(data: '0', length: lr - lv);
     }
     if (int(vv) < int(rr)) return inf;
     else if (int(vv) > int(rr)) return sup;
    }
    # 1.6.3.1 > 1.6.3
    if (nv < nr) return inf;
    else if (nv > nr) return sup;
    # if (v[i-1] == r[i-1]) return eq; - treated above
    # 2.30 and 2.30b (should I process this like alpha/beta or -r* ?
    v = eregmatch(string: ver_base, pattern: "^[0-9.]+([a-z]?)$");
    r = eregmatch(string: ref_base, pattern: "^[0-9.]+([a-z]?)$");
    if (! isnull(v) && ! isnull(r))
      if (v[1] < r[1]) return inf;
      else if (v[1] > r[1]) return sup;
      else if (v[1] == r[1]) return eq;
  }

  debug_print('qpkg_ver_cmp: do not known how to compare  ver=', ver, ' ',op, ' ref=', ref, '\n');
  return NULL;
}

function qpkg_cmp(pkg, version, range)
{
  local_var	v, cmp, ver, from_qpkg, l, ret, p, f;

  if (isnull(range)) return NULL;
#display("version=", version, "\trange=", range, "\n");
  v = split(range, sep: ' ');
  if (max_index(v) != 2)
  {
    debug_print('qpkg_cmp: bad format: ', range, '\tV=', v, '\n'); 
    return NULL;
  }
  cmp = chomp(v[0]); ver = chomp(v[1]);
#display("cmp=", cmp, "\tver=", ver, "\n");
  ret = qpkg_ver_cmp(ver: version, ref: ver, op: cmp);
#  if (ret > 0) display(version, " ", cmp, " ", ver, "\n");
  if (isnull(ret))
   debug_print('qpkg_cmp: compare failed - pkg=', pkg, ' version=', version, ' range=', range, '\n');
  return ret;
}

function qpkg_check(package, vulnerable, unaffected, arch)
{
  local_var	fU, fV, l, v, name, ver, my_arch, ret, from_qpkg, p, f;

  if (! qpkg_list) qpkg_list = get_kb_item("Host/Gentoo/qpkg-list");
  my_arch = get_kb_item("Host/Gentoo/arch");
  if (! qpkg_list) { return NULL; }

  if (arch && my_arch && my_arch >!< arch) return 0;

  l = egrep(string: qpkg_list, pattern: strcat(package, "-[0-9]"));
  # egrep returns an empty string if no match was found
  if (l != '')
    qpkg_tests_add(package);
  # several version of a same package may be installed
  ret = NULL;
  foreach from_qpkg (split(l, keep:0))
  {
     v = eregmatch(string: from_qpkg, icase: 1,
             pattern: '^[a-z0-9-]+/([a-z_-]|[^-][0-9])+-([0-9a-z._-]+)$');
     if (isnull(v))
     {
       #display("qpkg_check: cannot parse ", from_qpkg, "\n");
       # continue does not exist in 2.0.x and will do a parse error
     }
     else
     {
     name = v[1]; ver = v[2];

     foreach p (vulnerable)
     {
        fV = NULL; fU = NULL;

        f = qpkg_cmp(pkg: from_qpkg, version: ver, range: p);
        if (f == 1)
        {
          #display("vulnerable: ", p, "\n");
          fV = 1;
          debug_print(level: 2, 'Gentoo package ', from_qpkg, ' could be vulnerable - range=', p, '\n');
          break;
        }
        if (isnull(fV)) fV = f;
      }

     foreach p (unaffected)
     {
        f = qpkg_cmp(pkg: from_qpkg, version: ver, range: p);
        if (f == 1)
        {
          #display("unaffected: ", p, "\n");
          fU = 1;
          debug_print(level: 2, 'Gentoo package ', from_qpkg, ' is not vulnerable - range=', p, '\n');
          break;
        }
        if (isnull(fU)) fU = f;
      }
     if (fV > 0 && fU < 1)
     {
      debug_print('Gentoo package ', from_qpkg, ' is vulnerable - Unaffected versions are ', unaffected, '\n');
      qpkg_report_add(package:package, installed:ver, reference:unaffected);
      return 1;
     }
    }
   }
  return 0;
}


function qpkg_report_add(package, installed, reference)
{
  local_var fix, fix_str, op, ver;

  if (max_index(reference) == 0) fix_str = 'n/a';
  else
  {
    fix_str = '';
    foreach fix (reference)
    {
      ver = strstr(fix, ' ') - ' ';
      op = fix - ver - ' ';

      if (op == 'ge') op = '>=';
      else if (op == 'gt') op = '>';
      else if (op == 'rge') op = 'revision >=';
      else if (op == 'le') op = '<=';
      else if (op == 'lt') op = '<';
      else if (op == 'rle') op = 'revision <=';
      else if (op == 'eq') op = '=';
      else if (op == 'ne') op = '!=';
 
      fix_str += ', ' + op + ' ' + ver;
    }
    fix_str = substr(fix_str, 2);
  }
 
  qpkg_report += '  - Package           : ' + package + '\n' +
                 '    Installed version : ' + installed + '\n' +
                 '    Fixed version(s)  : ' + fix_str + '\n' +
                 '\n';
}


function qpkg_report_get()
{
  if ( strlen(qpkg_report)) return '\n' + qpkg_report;
  else return NULL;
}


function qpkg_tests_add()
{
  qpkg_tests = make_list(qpkg_tests, _FCT_ANON_ARGS[0]);
}


function qpkg_tests_get()
{
  local_var p, s;

  if (max_index(qpkg_tests) == 0) return NULL;
  s = "";
  foreach p (qpkg_tests)
    s += " / " + p;
	return substr(s, 3);
}
