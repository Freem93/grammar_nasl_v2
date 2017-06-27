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
# debian_package.inc
# $Revision: 1.20 $


# http://www.debian.org/doc/debian-policy/ch-controlfields.html#s-f-Version
# [epoch:]upstream_version[-debian_revision]

include('global_settings.inc');

##
# Internal value for storing report text
##
global_var deb_report;
deb_report = '';

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
# Adds package/reference info to the internal deb_report value 
#
# @param package Installed version of package
# @param reference Non-affected version of package
#
# @return No return
##
function deb_report_add(package, reference)
{
 deb_report += 'Remote package installed : ' + package + '\n' +
		'Should be : ' + reference + '\n';
}

##
# Returns internal deb_report value 
#
# @return newline + deb_report if it has a strlen value 
#         NULL otherwise
##
function deb_report_get()
{
 if ( strlen(deb_report) )
	return '\n' + deb_report;
 else
	return NULL;
}

##
# Compares two Debian version string pieces
#
# @param s1 First version string piece
# @param s2 Second version string piece
#
# @remark This function only looks at the first max_len pieces of each
#           for whichever is shorter
#
# @return 1 if s1 > s2 in version parts from left to right
#         -1 if s1 < s2 in version parts from left to right
#         0 if s1 and s2 are equal through lowest max_len
#         NULL if either version is an invalid format
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

  for(i=0; i < v1_len || i < v2_len; i ++)
  {
    if(v1[i] =~ "^[0-9.]+")
    {
      t1 = split(v1[i], sep:'.', keep:FALSE);
      t2 = split(v2[i], sep:'.', keep:FALSE);
      t1_len = max_index(t1);
      t2_len = max_index(t2);
  
      for (j = 0; j < t1_len || j < t2_len; j++)
      {
        if (int(t1[j]) < int(t2[j]))
          return -1;
        if (int(t1[j]) > int(t2[j]))
          return 1;
      }
    }
    else
    {
      if(v1[i] < v2[i])
        return -1;
      if(v1[i] > v2[i])
        return 1;
    }
  }
  return 0;
}

##
# Compares two complete Debian versions
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
function deb_ver_cmp(ver1, ver2)
{
  local_var	v1, v2, e1, e2, uv1, uv2, dr1, dr2, rc1, rc2, x;

  # Parse RCs
  rc1 = eregmatch(string: ver1, pattern: "^(.*)[.~\-+]rc([0-9]+)(.*)$", icase: 1);
  rc2 = eregmatch(string: ver2, pattern: "^(.*)[.~\-+]rc([0-9]+)(.*)$", icase: 1);
  if (! isnull(rc1))
  {
    ver1 = rc1[1] + rc1[3];
    rc1 = rc1[2];
  }
  if (! isnull(rc2))
  {
    ver2 = rc2[1] + rc2[3];
    rc2 = rc2[2];
  }

  v1 = eregmatch(string: ver1, pattern: "^([0-9]+:)?([^-]+)(-([a-z0-9+.-]+))?$", icase: 1);
  v2 = eregmatch(string: ver2, pattern: "^([0-9]+:)?([^-]+)(-([a-z0-9+.-]+))?$", icase: 1);
 
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
  if (! isnull(rc1) && ! isnull(rc2) && rc1 != rc2)
  {
    return int(rc1) - int(rc2);
  }
  x = deb_str_cmp(s1: dr1, s2: dr2);
  return x;
}

##
# Checks if package below a reference version is installed.
#
# @param prefix package name (ie: python)
# @param release Debian release number (optional)
# @param reference version and release number (ie: 2.6.6-3+squeeze7)
# @param min minimum version and release number to check (optional)
#
# @remark This function has the side-effect of modifying deb_report
#
# @return 1 if package installed and min <= package < reference
#              and Host OS release == release
#         0 otherwise
##
function deb_check(prefix, release, reference, min)
{
  local_var debver, dpkg_l, pkgver, release_trimmed;
  local_var installed, ver, v;

  if (get_kb_item("Host/uptrack-uname-r") && !get_kb_item("Host/uptrack-disable-file") && match(pattern:"kernel*", string:prefix)) return 0;

  debver = chomp(get_kb_item("Host/Debian/release"));
  if ( ! debver ) return 0; # Not debian

  # Try something smarter but slower below
  # if (debver && release != debver) return 0;

  dpkg_l = get_kb_item("Host/Debian/dpkg-l");
  installed = egrep(string: dpkg_l, pattern: '^ii +' + prefix + '(:\\w+)? +');
  if (! installed) return 0;
  ver = ereg_replace(	string: installed, replace: "\2",
  pattern: '^ii +' + prefix + '(:\\w+)? +([^ ]+) +.*$');
  if (ver == installed) return 0;	# cannot extract version

  # Here, we try to extract the "branch" from the installed package
  # I don't think that mixing sarge, woody and sid packages on a single
  # system is great, but it is possible.
  # However, the branch is not always included in the package name, and
  # Look at "DSA 865-1" for example. So we fall back to /etc/debian-release
  # and hope that such mix did not occur
  if (ereg(string: ver, pattern: '[0-9]$')) pkgver = debver; # or '4.0'?
  else if (ereg(string: ver, pattern: 'jessie[0-9]$')) pkgver  = '8.0';
  else if (ereg(string: ver, pattern: 'wheezy[0-9]$')) pkgver  = '7.0';
  else if (ereg(string: ver, pattern: 'squeeze[0-9]$')) pkgver = '6.0';
  else if (ereg(string: ver, pattern: 'lenny[0-9]$')) pkgver   = '5.0';
  else if (ereg(string: ver, pattern: 'etch[0-9]$')) pkgver    = '4.0';
  else if (ereg(string: ver, pattern: 'sarge[0-9]$')) pkgver   = '3.1';
  else if (ereg(string: ver, pattern: 'woody[0-9]$')) pkgver   = '3.0';
  else if (ereg(string: ver, pattern: 'potato[0-9]$')) pkgver  = '2.2';
  else if (ereg(string: ver, pattern: 'hamm[0-9]$')) pkgver    = '2.0';
  else pkgver = debver;

  release_trimmed = release;
  if (ereg(string: release_trimmed, pattern:"([7-9]|[1-9][0-9])\.[0-9][0-9]?"))
  {
    release_trimmed = eregmatch(string: release_trimmed, pattern:"([7-9]|[1-9][0-9])\.[0-9][0-9]?");
    release_trimmed = release_trimmed[1];
  }
  if (pkgver && release != pkgver && ! match(string: pkgver, pattern: release_trimmed+".*"))
  {
    return 0;
  }
  if (deb_ver_cmp(ver1: ver, ver2: reference) < 0)
  {
    # Added a check for a minimum version.
    if (isnull(min) || (deb_ver_cmp(ver1:ver, ver2:min) >= 0))
    {
      deb_report_add(package:prefix + "_" + ver, reference:prefix + "_" + reference);
      debug_print("debian_package[", get_host_ip(), "]: package ", prefix, "_", ver, " is vulnerable in Debian ", release, ". Upgrade to ", prefix, "_", reference, "\n");
      return 1;
    }
  }
  return 0;
}

