#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# vmware_esx_packages.inc
# $Revision: 1.6 $
#

include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");


global_var esx_missing_patches, esx_report;
global_var esx_pkg_l, esx_vib_l, esx_version, newest_bundle;

esx_missing_patches = make_list();
esx_pkg_l = NULL; esx_vib_l = NULL; esx_version = NULL; newest_bundle = NULL;
esx_report = '';

function init_esx_check(date)
{
  if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
  if (!get_kb_item("Host/VMware/release")) exit(0, "The host is not a VMware ESX / ESXi system.");

  if (! esx_version)
  {
    esx_version = get_kb_item("Host/VMware/version");
    if (! esx_version)
      exit(1, "The version of VMware ESX / ESXi is unknown.");
  }

  if (! esx_pkg_l)
  {
    esx_pkg_l = get_kb_item("Host/VMware/esxupdate");
  }

  if (esx_pkg_l)
  {
    if (! newest_bundle)
      newest_bundle = get_kb_item("Host/VMware/NewestBundle");
    if (newest_bundle && date <= newest_bundle)
    {
      debug_print('Advisory is older (', date, ') than the last installed bundle (', newest_bundle, ')\n');
      exit(0, "The advisory is older ("+date+") than the last installed bundle ("+newest_bundle+").");
    }
  }

  if (! esx_vib_l)
  {
    esx_vib_l = get_kb_item("Host/VMware/esxcli_software_vibs");
  }
}


#  esx-base              5.0.0-1.11.623860                    2012-04-03
#  ipmi-ipmi-devintf     39.1-4vmw.500.0.0.469512             2012-02-29
#  net-bnx2              2.0.15g.v50.11-5vmw.500.0.0.469512   2012-02-29
function vib_ver_cmp(ver, fix)
{
  local_var a_fix, a_ver, digit_mode_fix, digit_mode_ver, elem_fix, elem_ver, l_fix, l_ver;
  local_var i, j, j0, max;

  if (
    ("vmw" >< ver && "vmw" >!< fix) ||
    ("vmw" >!< ver && "vmw" >< fix)
  ) 
  {
    debug_print("Don't know how to compare version (", ver, ") with fixed version (", fix, ").\n");
    return NULL;
  }

  a_ver = split(ver, sep:".", keep:0);
  a_fix = split(fix, sep:".", keep:0);

  if (max_index(a_fix) < max_index(a_ver)) max = max_index(a_ver);
  else                                     max = max_index(a_fix);

  for (i=0; i<max; i++)
  {
    if (max_index(a_ver) <= i) return -1;
    if (max_index(a_fix) <= i) return 1;

    digit_mode_ver = 1;
    digit_mode_fix = 1;

    elem_ver = a_ver[i];
    elem_fix = a_fix[i];

    l_ver = strlen(elem_ver);
    l_fix = strlen(elem_fix);

    j0 = -1;
    for (j=0; j<l_ver && j<l_fix; j++)
    {
      if (elem_ver[j] != elem_fix[j]) break;
      if (elem_ver[j] !~ "[0-9]") j0 = j;
    }
    if (j0 >= 0)
    {
      j0 ++;

      if (j0 >= l_ver) a_ver[i] = "";
      else a_ver[i] = substr(elem_ver, j0);

      if (j0 >= l_fix) a_fix[i] = "";
      else a_fix[i] = substr(elem_fix, j0);
    }

    if (a_ver[i] !~ "^[0-9]+$") digit_mode_ver = 0;
    if (a_fix[i] !~ "^[0-9]+$") digit_mode_fix = 0;

    if (digit_mode_ver && digit_mode_fix)
    {
      if (int(a_ver[i]) != int(a_fix[i]))
        return int(a_ver[i]) - int(a_fix[i]);
    }
    else if (a_ver[i] != a_fix[i])
    {
      if (nondigit_vers_cmp(a:a_ver[i], b:a_fix[i]) < 0)
        return -1;
      else 
        return  1;
    }
  }
 return 0;
}

function esx_vib_report_add(vib, installed, reference)
{
  esx_report += '\n  VIB               : ' + vib + 
                '\n  Installed version : ' + installed +
                '\n  Fixed version     : ' + reference +
                '\n';
}

function esx_check(ver, patch, vib, patch_updates)
{
  local_var patch_update, v, date;
  local_var match, matches, my_vib, n, parts, r, vib_pat;

  if (ver != esx_version) return 0;

  if (patch)
  {
    if (! esx_pkg_l) exit(1, "The list of installed packages is empty.");

    debug_print('P=', patch, ' N=', newest_bundle, '\n');
    if (newest_bundle)
    {
      # Extract Year & Month from patch ID
      v = eregmatch(string: patch, pattern: "^ESXi?[0-9]+-(20[0-9][0-9])([0-9][0-9])[0-9]+-[A-Z]+$");
      date = strcat(v[1], '-', v[2], '-01');
      if (date <= newest_bundle)
      {
        debug_print('Patch ', patch, ' is older than the last installed bundle\n');
        return 0;
      }
    }
    if (egrep(pattern: '^[ \t]*'+patch+'[ \t]', string: esx_pkg_l))
    {
     debug_print('Patch ', patch, ' is installed on ', ver, '\n');
     return 0;
    }
    if (patch_updates)
    {
      foreach patch_update (patch_updates)
      {
        if (egrep(pattern: '^[ \t]*'+patch_update+'[ \t]', string: esx_pkg_l))
        {
         debug_print('Patch update', patch_update, ' is installed on ', ver, '\n');
         return 0;
        }
      }
    }
#    debug_print('Patch ', patch, ' is missing on ', ver, '\n');
    esx_missing_patches = make_list(esx_missing_patches, patch);
    return 1;
  }

  if (vib)
  {
    if (!esx_vib_l) exit(1, "The list of installed VIBs is empty.");

    # vibs can look like:
    #   VMware:esx-base:5.0.0-0.10.608089
    #   net-e1000:8.0.3.1-2vmw.500.0.7.515841
    parts = split(vib, sep:":", keep:0);
    n = max_index(parts);

    if (n < 2 || n >3)
    {
      err_print("invalid vib name ("+vib+")!");
      return 0;
    }

    my_vib = make_array();
    if (n == 3) my_vib["vendor"] = parts[0];
    my_vib["name"]    = parts[n-2];
    my_vib["version"] = parts[n-1];

    # nb: currently esx_vib_l doesn't have vendor info.
    vib_pat = strcat("^", my_vib["name"], "[ \t]+([0-9][^ \t]+)");
    matches = egrep(pattern:vib_pat, string:esx_vib_l);
    if (!matches) return 0;

    foreach match (split(matches, keep:FALSE))
    {
      parts = eregmatch(pattern:vib_pat, string:match);
      r = vib_ver_cmp(ver:parts[1], fix:my_vib["version"]);
      if (!isnull(r) && r < 0)
      {
        esx_vib_report_add(vib:my_vib["name"], installed:parts[1], reference:my_vib["version"]);
        return 1;
      }
      else return 0;
    }
  }
  else return 0;
}

function esx_report_get()
{
  local_var l, n, r;

  if ("ESXi" >< esx_version) l = "ESXi version";
  else l = "ESX version ";

  r = '\n  ' + l + ' : ' + esx_version + 
      '\n' +
      esx_report;

  n = max_index(esx_missing_patches);
  if (n == 1)
    r += '\n  Missing patch : ' + join(esx_missing_patches) + '\n';
  else if (n > 1)
    r += '\n  Missing patches : ' + join(esx_missing_patches, sep:'\n'+crap(data:' ', length:20)) + '\n';

  return r;
}
