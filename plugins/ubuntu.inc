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
# ubuntu.inc
#
# $Revision: 1.13 $
#


include("global_settings.inc");

##
# Storage value for release kb so we only need to fetch once.
##
global_var release;

##
# Storage value for package list kb so we only need to fetch once.
##
global_var dpkg_l;

##
# Storage value for if dpkg_l has been fixed up for linux packages.
##
global_var dpkg_fixup_flag;

##
# Internal storage value for reporting text on flag.
##
global_var _ubuntu_report;
_ubuntu_report = '';

##
# List storage of all remote packages found and checked
##
global_var _ubuntu_pkg_tests;
_ubuntu_pkg_tests = make_list();

##
# Array storage of all modified dpkg-l entries to point to their original versions
##
global_var _ubuntu_dpkg_edits;
_ubuntu_dpkg_edits = make_array();

##
# Translation array for determining what kinds of release candidate
# types are greater than others
##
global_var _ubuntu_rc_type = make_array(
  "rc", 3,
  "beta", 2,
  "alpha", 1
);

##
# Adds package/reference info to the internal _ubuntu_report value 
#
# @param package Installed version of package
# @param reference Non-affected version of package
#
# @return No return if package and reference are non-empty and non-null
#         else NULL
##
function ubuntu_report_add(package, reference)
{
  if ( isnull(package) || !strlen(package) || isnull(reference) || !strlen(reference) )
  {
    return NULL;
  }
  if (!isnull(_ubuntu_dpkg_edits[package]) && strlen(_ubuntu_dpkg_edits[package]))
    package = _ubuntu_dpkg_edits[package];
  if (!isnull(_ubuntu_dpkg_edits[reference]) && strlen(_ubuntu_dpkg_edits[reference]))
    reference = _ubuntu_dpkg_edits[reference];
  _ubuntu_report += '  - Installed package : ' + package + '\n' +
                    '    Fixed package     : ' + reference + '\n' +
                    '\n';
}

##
# Returns internal _ubuntu_report value 
#
# @return newline + _ubuntu_report if it has a strlen value 
#         NULL otherwise
##

function ubuntu_report_get()
{
  if (strlen(_ubuntu_report)) return '\n' + _ubuntu_report;
  else return NULL;
}

##
# Adds package to _ubuntu_pkg_tests list
#
# @anonparam First A full package/version combination from target system
##
function ubuntu_pkg_tests_add()
{
  local_var array, package;
  package = _FCT_ANON_ARGS[0];
  if (!package || !strlen(package)) return NULL;
  if (!isnull(_ubuntu_dpkg_edits[package]) && strlen(_ubuntu_dpkg_edits[package]))
    package = _ubuntu_dpkg_edits[package];
  _ubuntu_pkg_tests = make_list(_ubuntu_pkg_tests, package);
}

##
# Sorts and uniques entries in _ubuntu_pkg_tests list, returns as string
#
# @return Sorted, unique list of dpkgs from _ubuntu_pkg_tests in a string
#           separated by " / "
##
function ubuntu_pkg_tests_get()
{
  local_var p, s, pkg_tests_unique, pkg_tests_array, package;

  if (max_index(_ubuntu_pkg_tests) == 0) return NULL;
  pkg_tests_array = make_array();
  pkg_tests_unique = make_list();
  foreach package (_ubuntu_pkg_tests)
    if (!pkg_tests_array[package]++) pkg_tests_unique = make_list(pkg_tests_unique, package);
  pkg_tests_unique = sort(pkg_tests_unique);

  s = "";
  foreach p (pkg_tests_unique)
    s += " / " + p;
  return substr(s, 3);
}

##
# Parses numerical and string portions of a version string into a list
#
# @param ver_str version string
#
# @return list of parts of string broken into digit parts and other parts 
##
function deb_parse_ver_str(ver_str)
{
  local_var ret_val, is_num, tmp, i;

  ret_val = make_list();

  tmp = ver_str[0];
  is_num = FALSE;
  if(tmp =~ "[0-9.]") is_num = TRUE;
  tmp = '';

  for(i=0; i<strlen(ver_str); i++)
  {
    if(ver_str[i] =~ "[0-9.]" && is_num == FALSE)
    {
      is_num = TRUE;
      if(tmp != '') ret_val = make_list(ret_val, tmp);
      tmp = '';
    }
    else if(ver_str[i] !~ "[0-9.]" && is_num == TRUE)
    {
      is_num = FALSE;
      if(tmp != '') ret_val = make_list(ret_val, tmp);
      tmp = '';
    }
    tmp = tmp + ver_str[i];
  }

  if(tmp != '') ret_val = make_list(ret_val, tmp);

  return ret_val;
}


##
# Compares two version string pieces
#
# @param s1 First version string piece
# @param s2 Second version string piece
#
# @remark If one string has more parts than the other and they're identical
#           to the limit of the shorter, the longer one is decided greater.
#
# @return 1 if s1 > s2 in version parts from left to right
#         -1 if s1 < s2 in version parts from left to right
#         0 if s1 and s2 are equal
##
function deb_str_cmp(s1, s2)
{
  local_var v1, v2, v1_len, v2_len,
            t1, t2, t1_len, t2_len,
            i,  j;

  v1 = deb_parse_ver_str(ver_str:s1);
  v2 = deb_parse_ver_str(ver_str:s2);

  v1_len = max_index(v1);
  v2_len = max_index(v2);

  for(i=0; i < v1_len && i < v2_len; i ++)
  {
    # Numeric comparisons
    if(v1[i] =~ "^[0-9.]+")
    {
      t1 = split(v1[i], sep:'.', keep:FALSE);
      t2 = split(v2[i], sep:'.', keep:FALSE);
      t1_len = max_index(t1);
      t2_len = max_index(t2);

      for (j = 0; j < t1_len && j < t2_len; j++)
      {
        if (int(t1[j]) < int(t2[j]))
          return -1;
        if (int(t1[j]) > int(t2[j]))
          return 1;
      }
      # End of shared distance. If either has more at this point.
      # it is the greater.
      if (t1_len < t2_len)
        return -1;
      if (t1_len > t2_len)
        return 1;
    }
    else
    {
      # String comparisons
      if(v1[i] < v2[i])
        return -1;
      if(v1[i] > v2[i])
        return 1;
    }
  }
  # End of shared distance. Return based on what has anything left,
  # or 0 if they're equal.
  if (v1_len < v2_len)
    return -1;
  if (v1_len > v2_len)
    return 1;
  return 0;
}

##
# Compares two complete Ubuntu versions
#
# @param ver1 First version
# @param ver2 Second version
#
# @remark This function will remove RC entries from versions and then consider
#           which is greater if the version (not release) part is equal.
#
# @return 1 or more if ver1 > ver2 in version parts from left to right
#         -1 or less if ver1 < ver2 in version parts from left to right
#         0 if versions are equal
#         NULL if either version is an invalid format
##
function ubuntu_ver_cmp(ver1, ver2)
{
  local_var v1, v2, e1, e2, uv1, uv2, dr1, dr2, rc1, rc2, x, rctype1, rctype2;

  # Parse RCs. Treat alphas and betas the same as RCs.
  rc1 = eregmatch(string: ver1, pattern: "^(.*)[.~\-+](rc|alpha|beta)([0-9]+)(.*)$", icase: 1);
  rc2 = eregmatch(string: ver2, pattern: "^(.*)[.~\-+](rc|alpha|beta)([0-9]+)(.*)$", icase: 1);
  if (! isnull(rc1))
  {
    ver1 = rc1[1] + rc1[4];
    rctype1 = rc1[2];
    rc1 = rc1[3];
  }
  if (! isnull(rc2))
  {
    ver2 = rc2[1] + rc2[4];
    rctype2 = rc2[2];
    rc2 = rc2[3];
  }

  v1 = eregmatch(string: ver1, pattern: "^([0-9]+:)?([^-]+)(-([a-z0-9+.~-]+))?$", icase: 1);
  v2 = eregmatch(string: ver2, pattern: "^([0-9]+:)?([^-]+)(-([a-z0-9+.~-]+))?$", icase: 1);

  if (isnull(v1) || isnull(v2)) return NULL;
  e1 = int(v1[1]); uv1 = v1[2]; dr1 = v1[4];
  e2 = int(v2[1]); uv2 = v2[2]; dr2 = v2[4];

  if (e1 != e2) return e1 - e2;
  x = deb_str_cmp(s1: uv1, s2: uv2);
  if (x) return x;
  if (! isnull(rc1) && isnull(rc2))
  {
    return -1;
  }
  if (isnull(rc1) && ! isnull(rc2))
  {
    return 1;
  }
  if (! isnull(rc1) && ! isnull(rc2) && (rc1 != rc2 || rctype1 != rctype2) )
  {
    # If different type, return based on which type is higher
    if (rctype1 != rctype2)
    {
      return _ubuntu_rc_type[rctype1] - _ubuntu_rc_type[rctype2];
    }
    else
    {
      # If same type, return based on high rc number
      return int(rc1) - int(rc2);
    }
  }
  x = deb_str_cmp(s1: dr1, s2: dr2);
  return x;
}

##
# Determines shortened name and metapackage name for the dpkg
#
# @param dpkg package name to parse
#
# @return my_dpkg array containing key-values about dpkg
##
function parse_linux_dpkg_name(dpkg)
{
  local_var elems, i, name, version, prefix, name_version, name_version_major, suffix, name_pieces;
  local_var my_dpkg, metapackage;

  if (isnull(dpkg) || !strlen(dpkg)) return NULL;
  my_dpkg["line"]  = dpkg;
  # Trim off character status code and spacing.
  dpkg = ereg_replace(string:dpkg, pattern:"^ii\s+", replace:"");
  dpkg = ereg_replace(string:dpkg, pattern:" {3,}", replace:"  ");
  elems = split(dpkg, sep:"  ", keep:0);
  name = elems[0];
  version = elems[1];

  if ( ereg(string:name, pattern:"\d+\.\d+\.\d+-\d+") ) {
    name_pieces = eregmatch(string:name, pattern:"^(.*)-(\d+\.\d+\.\d+-\d+)-?(.*)$");
    prefix = name_pieces[1];
    name_version = name_pieces[2];
    suffix = name_pieces[3];
    name_version_major = eregmatch(string:name_version, pattern:"^(\d+\.\d+)\.");
    name_version_major = name_version_major[1];
    metapackage = prefix + '-' + name_version_major;
    if (!isnull(suffix) && strlen(suffix)) {
      metapackage += '-' + suffix;
    }
  } else {
    metapackage = name;
  }

  my_dpkg["name"]        = name;
  my_dpkg["version"]     = version;
  my_dpkg["metapackage"] = metapackage;
  my_dpkg["line"]        = str_replace(string:my_dpkg["line"],find:name,replace:metapackage);
  _ubuntu_dpkg_edits[metapackage + "_" + version] = name + "_" + version;

  return my_dpkg;
}


##
# Changes dpkg-l so that only a single copy of each package that
# begins with "linux-", the latest, appears in the dpkg list
#
# @anonparam First List of dpkgs, joined with newlines as in most
#              dpkg-l KB entries
#
# @remark Only applies to linux packages.
#
# @return Revised copy of dpkg-l with only the latest linux package
#
##
function fixup_dpkg_list()
{
  local_var lines, line, arg;
  local_var ret;
  local_var linux_dpkg;
  local_var linux_dpkgs;

  arg = _FCT_ANON_ARGS[0];
  if (isnull(arg) || !strlen(arg)) return NULL;

  lines = split(arg, keep:FALSE);
  foreach line ( lines )
  {
    if ( line =~ "^ii +linux-" )
    {
      linux_dpkg = parse_linux_dpkg_name(dpkg:line);
      if ( isnull(linux_dpkgs[linux_dpkg["metapackage"]]) ) linux_dpkgs[linux_dpkg["metapackage"]] = linux_dpkg;
      else
      {
        if ( ubuntu_ver_cmp(ver1: linux_dpkg["version"], ver2: linux_dpkgs[linux_dpkg["metapackage"]]["version"]) > 0) {
          linux_dpkgs[linux_dpkg["metapackage"]] = linux_dpkg;
        }
      }
    }
    else ret += line + '\n';
  }

  foreach linux_dpkg ( sort(keys(linux_dpkgs)) )
  {
    ret += linux_dpkgs[linux_dpkg]["line"] + '\n';
  }
  return ret;
}


##
# Checks if package below a reference version is installed.
#
# @param pkgname package name (ie: python)
# @param osver OS version 
# @param pkgver version and release number (ie: 2.6.6-3+squeeze7)
#
# @remark This function has the side-effect of modifying ubuntu_report
#
# @return 0 if uptrack is installed but disable file unavailable
#              and package begins with kernel
#         version string installed if package installed and
#              package < pkgver and Host OS release == osver 
#         NULL otherwise
##
function ubuntu_check(osver, pkgname, pkgver)
{
  local_var installed, ver, v;
  local_var name_pieces, prefix, name_version, suffix, name_version_major, name_orig;
  if (get_kb_item("Host/uptrack-uname-r") && !get_kb_item("Host/uptrack-disable-file") && ( match(pattern:"kernel*", string:pkgname) || match(pattern:"linux*", string:pkgname) ) ) return 0;

  if (! release) release = chomp(get_kb_item("Host/Ubuntu/release"));
  if (release != osver) return NULL;

  if (!dpkg_l) dpkg_l = get_kb_item("Host/Debian/dpkg-l");

  if ( pkgname =~ "^linux-" ) 
  {
    if (!dpkg_fixup_flag) {
      dpkg_l = fixup_dpkg_list(dpkg_l);
      dpkg_fixup_flag = 1;
    }
    # Trim down dpkg_list to match the fixups
    if ( ereg(string:pkgname, pattern:"\d+\.\d+\.\d+-\d+") ) {
      name_orig = pkgname;
      name_pieces = eregmatch(string:pkgname, pattern:"^(.*)-(\d+\.\d+\.\d+-\d+)-?(.*)$");
      prefix = name_pieces[1];
      name_version = name_pieces[2];
      suffix = name_pieces[3];
      name_version_major = eregmatch(string:name_version, pattern:"^(\d+\.\d+)\.");
      name_version_major = name_version_major[1];
      pkgname = prefix + '-' + name_version_major;
      if (!isnull(suffix) && strlen(suffix)) {
        pkgname += '-' + suffix;
      }
      _ubuntu_dpkg_edits[pkgname + "_" + pkgver] = name_orig + "_" + pkgver;
    }
  }

  # Only packages whose lines in dpkg -l actually begin with 'ii' are
  # actually installed.
  installed = egrep(string: dpkg_l, pattern: '^ii +' + pkgname + '(:\\w+)? +');
  if (! installed) return NULL;

  ver = ereg_replace(string: installed, replace: "\2",
    pattern: '^ii +' + pkgname + '(:\\w+)? +([^ ]+) +.*$');
  if (ver == installed) return NULL; # cannot extract version
  ubuntu_pkg_tests_add( pkgname + '_' + ver );
  if (ubuntu_ver_cmp(ver1: ver, ver2: pkgver) < 0)
  {
    ubuntu_report_add(package:pkgname+"_"+ver, reference:pkgname+"_"+pkgver);
    return ver;
  }
  return NULL;
}
