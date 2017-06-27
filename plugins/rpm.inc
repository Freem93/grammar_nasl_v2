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
# rpm.inc
# $Revision: 1.85 $
#

# Internal use globals
global_var __pkg_tests, __rpm_report;
##
# List storage of all remote packages found and checked
##
__pkg_tests = make_list();

##
# String containing all affected package reporting
##
__rpm_report = '';

##
# Changes rpm-list so that only a single copy of each package that
# begins with "kernel-", the latest, appears in the rpm-list
#
# @anonparam First List of rpms, joined with newlines as in most
#              rpm-list KB entries
#
# @remark Only applies to kernel packages.
#
# @return Revised copy of rpm-list with only the latest kernel
#           packages
##
function fixup_rpm_list()
{
  local_var lines, line;
  local_var ret;
  local_var key;
  local_var array;
  local_var rpm;

  lines = split(_FCT_ANON_ARGS[0], keep:FALSE);
  foreach line ( lines )
  {
    if ( line =~ "^(vz)?kernel-" )
    {
      rpm = parse_rpm_name(rpm:line);
      if ( isnull(array[rpm["name"]]) ) array[rpm["name"]] = line;
      else
      {
        if ( rpm_cmp(rpm:line, reference:array[rpm["name"]], allowmaj:TRUE) > 0 )
        {
          array[rpm["name"]] = line;
        }
      }
    }
    else ret += line + '\n';
  }

  foreach key ( keys(array) )
  {
    ret += array[key] + '\n';
  }
  return ret;
}

##
# If string begins with "rhel#" (insensitive) change it to "el"
#
# @anonparam First string from part of an rpm version string
#
# @return anonymous parameter with "rhel" changed to "el" if it began
#           with "rhel#"
##
function filter_rh_inconstency()
{
 local_var a;
 a = _FCT_ANON_ARGS[0];
 if ( tolower(a) =~ "^rhel[0-9.]+$" )
  a = ereg_replace(pattern:"^rhel", replace:"el", string:a, icase:TRUE);

 return a;
}

##
# Adds package to __pkg_tests list
#
# @anonparam First A full rpm name from target system
##
function pkg_tests_add()
{
 local_var array;
 array = split(chomp(_FCT_ANON_ARGS[0]), sep:'|', keep:FALSE);
  __pkg_tests = make_list(__pkg_tests, array[0]);
}

##
# Sorts and uniques entries in __pkg_tests list, returns as string
#
# @return Sorted, unique list of rpms from __pkg_tests in a string
#           separated by " / "
##
function pkg_tests_get()
{
  local_var p, s, pkg_tests_unique, pkg_tests_array, package;

  if (max_index(__pkg_tests) == 0) return NULL;
  pkg_tests_array = make_array();
  pkg_tests_unique = make_list();
  foreach package (__pkg_tests)
    if (!pkg_tests_array[package]++) pkg_tests_unique = make_list(pkg_tests_unique, package);
  pkg_tests_unique = sort(pkg_tests_unique);

  s = "";
  foreach p (pkg_tests_unique)
    s += " / " + p;
  return substr(s, 3);
}

##
# Adds text to to __rpm_report string indicating an affected package
#
# @param package Affected package install string
# @param Release Fixed package install string
##
function rpm_report_add(package, reference)
{
 local_var array;
 array = split(package, sep:'|', keep:FALSE);
 package = array[0];
 __rpm_report += 'Remote package installed : ' + package + '\n' +
                 'Should be                : ' + reference + '\n\n';

}

##
# Returns __rpm_report string
#
# @return __rpm_report prepended by a \n if __rpm_report has string
#           length
#         NULL otherwise
##
function rpm_report_get()
{
  if ( strlen(__rpm_report) )
   return '\n' + __rpm_report;
 else
  return NULL;
}

##
# Parses name, version, release, and other necessary flags out of rpm
#
# @param rpm rpm string to parse
# @param yank optional string to remove from rpm
#
# @return my_rpm array containing key-values about rpm package
##
function parse_rpm_name(rpm, yank)
{
 local_var elems, num, i, name;
 local_var my_rpm, pat, ep_str, cf_str, sat_str, scl_str;

 pat = "md[kv]20[01][0-9]\.[0-9]$";
 rpm = ereg_replace(string: rpm, pattern: pat, replace: "");
 yank = ereg_replace(string: yank, pattern: pat, replace: "");

 elems = split(rpm, sep:"|", keep:0);
 if ( max_index(elems) > 1 )
 {
  my_rpm["epoch"] = elems[1];
#  my_rpm["keyid"] = elems[2];
  rpm = elems[0];
 }
 elems = split(rpm, sep:"-", keep:0);
 num = max_index(elems);
 name = elems[0];
 for ( i = 1; i < num - 2 ; i ++ )
 {
  name += "-" + elems[i];
 }

 my_rpm["name"]     = name;
 my_rpm["version"]  = elems[num - 2];
 my_rpm["release"]  = elems[num - 1];
 my_rpm["jpp_flag"] = "0";
 my_rpm["sat_flag"] = "0";
 my_rpm["cf_flag"]  = "0";
 my_rpm["scl_flag"] = "0";

 cf_str = eregmatch(string:my_rpm["release"], pattern:"^.*cf$");
 if (!isnull(cf_str)) {
   my_rpm["cf_flag"] = "1";
 }

 sat_str = eregmatch(string:my_rpm["release"], pattern:"^.*sat$");
 if (!isnull(sat_str)) {
   my_rpm["sat_flag"] = "1";
 }

 scl_str = eregmatch(string:my_rpm["release"], pattern:"^.*\.alt$");
 if (!isnull(scl_str)) {
   my_rpm["scl_flag"] = "1";
 }

 if ( "jpp" >< my_rpm["release"]) {
   my_rpm["jpp_flag"] = "1";
 }

 my_rpm["ep_flag"] = "0";
 if ( ".ep" >< my_rpm["release"]) {
   ep_str = eregmatch(string:my_rpm["release"], pattern:"^.*\.ep(\d+)\..*$");
   if (!isnull(ep_str))
     my_rpm["ep_flag"] = ep_str[1];
 }

 if ( yank ) {
  my_rpm["version"]  -= yank;
        my_rpm["release"] -= yank;
        my_rpm["epoch"] -= yank;
 }

 return my_rpm;
}

##
# Checks first values of two version strings against each other,
#   returns difference of major version
#
# @param a first version string
# @param b second version string
#
# @return integer difference between first octet of a and b
##
function maj_cmp(a, b)
{
 local_var array_a, array_b, i, max;
 local_var e;

 array_a = split(a, sep:".", keep:0);
 array_b = split(b, sep:".", keep:0);


 return int(array_a[0]) - int(array_b[0]);
}

##
# Returns ord() value of anonymous parameter, added 255 if it's
#   between 0 and 9, and returning 0 if it's a space
#
# @anonparam First a single character
#
# @return normalized character value
##
function normalize_value()
{
 local_var val;

 val = _FCT_ANON_ARGS[0];

 if ( val == ord(" ") ) return 0;
 if ( val >= ord("0") && val <= ord("9") )
  val += 255;
 return val;
}

##
#Compares strings a and b and returns based on which
#   is greater textwise if applicable
#
# @param a version string piece
# @param b version string piece
#
# @remark Compares normalized ord data to determine which is greater
# @remark Fills in shorter strings with \0s
#
# @return -1 RPM_OLDER if normalized a < normalized b
#          0 RPM_EQUAL if normalized a == normalized b
#          1 RPM_NEWER if normalized a > normalized b
##
function generic_str_cmp(a,b)
{
 local_var n, i, val_a, val_b;
 local_var retval;


 if ( strlen(a) < strlen(b) )
   a = strcat(a, crap(data:'\x00', length:strlen(b) - strlen(a)));
 else if ( strlen(a) > strlen(b) )
   b = strcat(b, crap(data:'\x00', length:strlen(a) - strlen(b)) );

 n = strlen(a);
 retval = 0;
 for ( i = 0 ; i < n ; i ++ )
 {
   val_a = normalize_value(ord(a[i]));
   val_b = normalize_value(ord(b[i]));
   if ( val_a > val_b )
  return 1;
   else if ( val_a < val_b )
  return -1;
 }

 return 0;
}

##
#Compares strings a and b and returns based on which
#   has an lower numeric portion or feeds into generic_str_cmp
#   if it's purely non-digit
#
# @param a version string piece
# @param b version string piece
#
# @remark Calls generic_str_cmp if no digits at front/back of both
#
# @return -1 RPM_OLDER if a starts with a digit and b doesn't ||
#                         a's digits in front are < b's digits
#                           in front ||
#                         a's digits in back are < b's digits
#                           in back ||
#                         a normalized < b normalized
#          0 RPM_EQUAL if a and b's digits are equal
#          1 RPM_NEWER if b starts with a digit and a doesn't ||
#                         b's digits in front are < a's digits
#                           in front ||
#                         b's digits in back are < a's digits
#                           in back ||
#                         b normalized < a normalized
##
function nondigit_vers_cmp(a,b)
{
 local_var ia, ib;
 local_var aa, ab;
 local_var s;

 if ( a =~ "^[0-9]" && b !~ "^[0-9]" )
  return 1;
 else if ( b =~ "^[0-9]" && a !~ "^[0-9]" )
  return -1;

 if ( a =~ "^[0-9]" && b =~ "^[0-9]" )
 {
  aa = eregmatch(string:a, pattern:"^([0-9]*)(.*)$");
  ab = eregmatch(string:b, pattern:"^([0-9]*)(.*)$");
  ia = int(aa[1]);
  a = aa[2];

  ib = int(ab[1]);
  b = ab[2];
  s = 1;
 }
 else if (a =~ "^[^0-9]+[0-9]+$" && b =~ "^[^0-9]+[0-9]+$" )
 {
  aa = eregmatch(string:a, pattern:"^([^0-9]*)([0-9]*)$");
  ab = eregmatch(string:b, pattern:"^([^0-9]*)([0-9]*)$");
  ia = int(aa[2]);
  a = aa[1];

  ib = int(ab[2]);
  b = ab[1];
  s = 2;
  if ( a < b )
  return -1;
  else if ( a > b )
  return 1;
 }
 else
 {
  return generic_str_cmp(a:a,b:b);
 }

 if ( strlen(aa[s]) && strlen(ab[s]) )
 {
 if ( ia < ib )
  return -1;
 else if ( ia > ib )
  return 1;
 }

 if ( strlen(a) != 0 && strlen(b) == 0 ) return 1;
 if ( strlen(b) != 0 && strlen(a) == 0 ) return -1;

 if ( a < b )
  return -1;
 else if ( a > b )
  return 1;
 else
  return 0;
}

##
#Compares version strings a and b and returns based on which
#   is lower
#
# @param a version string with . separator
# @param b version string with . separator
#
# @remark As it goes through different octets, it throws away the
#           largest identical parts ending in nondigits as it can
#
# @return -1 RPM_OLDER if an octet of a < that octet of b ||
#                         a == b for all a octets but b has more
#          0 RPM_EQUAL if a and b are equal
#          1 RPM_NEWER if if an octet of b < that octet of a ||
#                         a == b for all b octets but a has more
##
function vers_cmp(a, b)
{
 local_var array_a, array_b, i, max;
 local_var digit_mode_a, digit_mode_b;
 local_var elem_a, elem_b, j, la, lb, j0;

 array_a = split(tolower(a), sep:".", keep:0);
 array_b = split(tolower(b), sep:".", keep:0);

 if ( max_index(array_b) < max_index(array_a))
  max = max_index(array_a);
 else
  max = max_index(array_b);

 for ( i = 0 ; i < max ; i ++ )
 {
  digit_mode_a = 1;
  digit_mode_b = 1;
  if ( max_index(array_a) <= i ) return -1;
  if ( max_index(array_b) <= i ) return 1;

  array_a[i] = filter_rh_inconstency(array_a[i]);
  array_b[i] = filter_rh_inconstency(array_b[i]);

  elem_a = array_a[i];
  elem_b = array_b[i];
  la = strlen(elem_a);
  lb = strlen(elem_b);
  j0 = -1;
  for (j=0; j<la && j<lb; j++)
  {
   if (elem_a[j] != elem_b[j]) break;
   if (elem_a[j] !~ "[0-9]") j0 = j;
  }
  if (j0 >= 0)
  {
   j0 ++;

   if (j0 >= la)
     array_a[i] = "";
   else
    array_a[i] = substr(elem_a, j0);

   if (j0 >= lb)
     array_b[i] = "";
   else
    array_b[i] = substr(elem_b, j0);
  }

  if ( array_a[i] !~ "^[0-9]+$" ) digit_mode_a = 0;
  if ( array_b[i] !~ "^[0-9]+$" ) digit_mode_b = 0;

  if ( digit_mode_a && digit_mode_b )
      {
       if ( int(array_a[i]) != int(array_b[i]) )
         return int(array_a[i]) - int(array_b[i]);
      }
  else if ( array_a[i] != array_b[i] )
     {
        if ( nondigit_vers_cmp(a:array_a[i], b:array_b[i]) < 0 )
    return -1;
  else
    return  1;
     }
 }

 return 0;
}

##
# Return codes for rpm_cmp and rpm_check
##
RPM_OLDER   = -1;
RPM_EQUAL    = 0;
RPM_NEWER    = 1;
RPM_MISMATCH = 2;

##
# Return codes for _check_release_strings()
##
RELEASE_MISMATCH = -2;
RELEASE_MISSING = -3;
RPMS_MISSING = -4;

##
# Compares the rpm and reference and returns based on which
#   is greater if applicable
#
# @param rpm complete rpm string from system's rpm list
# @param reference complete rpm string passed from plugin
# @param yank string of data to -= remove from version string and epoch
# @param epoch optional epoch time to compare rpm argument against
# @param allowmaj optional flag to cause function not to return RPM_EQUAL
#              if the major version (the 24 in 24.1.23) differs on rpm and
#              reference
#
# @remark Default behavior is to return RPM_EQUAL if the major versions
#              for rpm and reference are different, treating as entirely
#              different packages.
#
# @return -1 RPM_OLDER if rpm and reference are for same package and
#              rpm's epoch < epoch (if supplied) or
#              rpm's version < reference version or
#              rpm's release < reference release (if versions equal)
#          0 RPM_EQUAL if rpm and reference package/version/release are
#              all equal or if the major version of each is different and
#              allowmaj is NULL or FALSE
#          1 RPM_NEWER if rpm and reference are for same package and
#              rpm's epoch > epoch (if supplied) or
#              rpm's version > reference version or
#              rpm's release > reference release (if versions equal)
#          2 RPM_MISMATCH if rpm and reference are for different packages
#              or if one or more supplied flags for each do not match
##
function rpm_cmp(rpm, reference, yank, epoch, allowmaj)
{
 local_var my_rpm, my_reference, eq, ep;

 my_rpm = parse_rpm_name(rpm:rpm, yank:yank);
 my_reference = parse_rpm_name(rpm:reference, yank:yank);

 if (my_rpm["name"] != my_reference["name"])
 {
   return RPM_MISMATCH;
 }

 if (my_rpm["ep_flag"] != my_reference["ep_flag"])
 {
   return RPM_MISMATCH;
 }

 if (my_rpm["jpp_flag"] != my_reference["jpp_flag"])
 {
   return RPM_MISMATCH;
 }

 if (my_rpm["sat_flag"] != my_reference["sat_flag"])
 {
   return RPM_MISMATCH;
 }

 if (my_rpm["cf_flag"] != my_reference["cf_flag"])
 {
   return RPM_MISMATCH;
 }

 if (my_rpm["scl_flag"] != my_reference["scl_flag"])
 {
   return RPM_MISMATCH;
 }

 if ( epoch )
  {
   eq = int(my_rpm["epoch"]) - int(epoch);
   if (eq < 0) return RPM_OLDER;
   if (eq > 0) return RPM_NEWER;
  }

 # for the redhat release package, only compare like versions
 # e.g. compare redhat-release-3ES-a.b.c and redhat-release-3ES-x.y.z,
 #      but not redhat-release-3ES-a.b.c and redhat-release-3WS-x.y.z
 if (
   my_reference["name"] == "redhat-release" &&
   my_rpm["version"] != my_reference["version"]
 )
 {
   return RPM_MISMATCH;
 }
 else
 {
   # nb: versioning for the perl-Module-Build package is not ordered
   # numerically (eg, 0.40 > 0.3500)
   if (my_reference["name"] == "perl-Module-Build")
   {
     if (my_rpm["version"] =~ "^0\.[0-9]{4}($|[^0-9])" || my_reference["version"] =~ "^0\.[0-9]{4}($|[^0-9])")
     {
       my_rpm["version"] = ereg_replace(pattern:"^(0\.[0-9][0-9])\.", replace:"\1"+"00.", string:my_rpm["version"]);
       my_reference["version"] = ereg_replace(pattern:"^(0\.[0-9][0-9])\.", replace:"\1"+"00.", string:my_reference["version"]);
     }
     else if (my_rpm["version"] =~ "^0\.[0-9]{5}($|[^0-9])" || my_reference["version"] =~ "^0\.[0-9]{5}($|[^0-9])")
     {
       my_rpm["version"] = ereg_replace(pattern:"^(0\.[0-9][0-9])\.", replace:"\1"+"00.", string:my_rpm["version"]);
       my_reference["version"] = ereg_replace(pattern:"^(0\.[0-9][0-9])\.", replace:"\1"+"00.", string:my_reference["version"]);
     }
   }

   eq = maj_cmp(a:my_rpm["version"], b:my_reference["version"]);
   if ( eq != 0 && (isnull(allowmaj) || allowmaj == FALSE )) return RPM_EQUAL;

   eq = vers_cmp(a:my_rpm["version"], b:my_reference["version"]);
   if (eq > 0) return RPM_NEWER;
   if (eq < 0) return RPM_OLDER;
 }

 eq = vers_cmp(a:my_rpm["release"], b:my_reference["release"]);
 if (eq > 0) return RPM_NEWER;
 if (eq < 0) return RPM_OLDER;
 return RPM_EQUAL;
}

##
# Combs through the potential release strings and rpm_lists to identify
#              the release and rpm-list on system, if applicable
#
# @param release optional argument to compare release string on system
#              against
#
# @remark Default behavior is to return an array containing keys for
#              "parsed_release" and "rpm-list". In the case of errors
#              (which will cause the calling functions to return 0)
#              we return an integer less than 0. 
#
# @return array with keys "parsed_release" and "rpm-list" if a valid
#              release and rpm-list were found
#         -2 RELEASE_MISMATCH if release argument and parsed_release
#              don't match
#         -3 RELEASE_MISING if unable to parse release
#         -4 RPMS_MISSING if the "rpm-list" for a "parsed_release" is
#              null or empty
##
function _check_release_strings(release)
{
  local_var rh_release, ala_release, suse_release, mdk_release, mlos_release;
  local_var xenserver_release, ovs_release, centos_release, ol_num, sl_num, parsed_release;
  local_var rhel_num, fc_num, centos_num, rpms, results, regex_results;
  local_var rhel_pattern, fedora_pattern, fedora_core_pattern;
  local_var ol_pattern, sl_pattern, centos_pattern, centos_old_pattern;
  local_var euler_pattern, euler_release, euler_num;
  local_var virtuozzo_pattern, virtuozzo_release, virtuozzo_num;


  rh_release = get_kb_item("Host/RedHat/release");
  ala_release = get_kb_item("Host/AmazonLinux/release");
  suse_release = get_kb_item("Host/SuSE/release");
  mdk_release = get_kb_item("Host/Mandrake/release");
  ovs_release = get_kb_item("Host/OracleVM/release");
  centos_release = get_kb_item("Host/CentOS/release");
  mlos_release = get_kb_item("Host/McAfeeLinux/release");
  xenserver_release = get_kb_item("Host/XenServer/release");
  euler_release = get_kb_item("Host/EulerOS/release");
  virtuozzo_release = get_kb_item("Host/Virtuozzo/release");

  rhel_pattern = "Red Hat Enterprise Linux.*release ([3-7])(\D|$)";
  fedora_pattern = "Fedora release ([7-9]|1[0-9]|2[0-5])(\D|$)";
  fedora_core_pattern = "Fedora Core release ([1-6])(\D|$)";
  ol_pattern = "Oracle .*Linux .*release ([3-7])(\D|$)";
  sl_pattern = "Scientific Linux release ([3-7])(\D|$)";
  centos_pattern = "CentOS(?: Linux)? release ([6-7])(\D|$)";
  centos_old_pattern = "CentOS release ([3-5])(\D|$)";
  euler_pattern = "EulerOS release ([1-2]\.[0-9])(\D|$)";
  virtuozzo_pattern = "Virtuozzo Linux release ([6-7])\.[0-9](\D|$)";

  if ( !isnull(ala_release) && strlen(ala_release) > 0 && stridx(ala_release, "ALA") == 0 )
    parsed_release = ala_release;
  else if ( "MDK" >< mdk_release )
    parsed_release = mdk_release;
  else if ( !isnull(ovs_release) && strlen(ovs_release) > 0 && stridx(ovs_release, "OVS") == 0 && ereg(pattern:"^(OVS\d+\.\d+)\.", string:ovs_release) )
  {
    regex_results = eregmatch(pattern:"^(OVS\d+\.\d+)\.", string:ovs_release);
    if (!isnull(regex_results)) parsed_release = regex_results[1];
  }
  else if ( "SLED" >< suse_release || "SLES" >< suse_release || "SUSE" >< suse_release )
    parsed_release = suse_release;
  else if ( "MLOS" >< mlos_release )
    parsed_release = mlos_release;
  else if ( "XS" >< xenserver_release )
    parsed_release = xenserver_release;
  else if ( egrep(pattern:rhel_pattern, string:rh_release) )
  {
    regex_results = eregmatch(pattern:rhel_pattern, string:rh_release);
    if (!isnull(regex_results))
    {
      rhel_num =  regex_results[1];
      parsed_release = "RHEL" + rhel_num;
    }
  }
  else if ( egrep(pattern:"Red Hat.*(Enterprise|Advanced).*release 2\.1", string:rh_release) )
    parsed_release = "RHEL2.1";
  else if ( egrep(pattern:fedora_pattern, string:rh_release) )
  {
    regex_results = eregmatch(pattern:fedora_pattern, string:rh_release);
    if (!isnull(regex_results))
    {
      fc_num =  regex_results[1];
      parsed_release = "FC" + fc_num;
    }
  }
  else if ( egrep(pattern:fedora_core_pattern, string:rh_release) )
  {
    regex_results = eregmatch(pattern:fedora_core_pattern, string:rh_release);
    if (!isnull(regex_results))
    {
      fc_num =  regex_results[1];
      parsed_release = "FC" + fc_num;
    }
  }
  else if ( egrep(pattern:ol_pattern, string:rh_release) )
  {
    regex_results = eregmatch(pattern:ol_pattern, string:rh_release);
    if (!isnull(regex_results))
    {
      ol_num =  regex_results[1];
      parsed_release = "EL" + ol_num;
    }
  }
  else if ( egrep(pattern:sl_pattern, string:rh_release) )
  {
    regex_results = eregmatch(pattern:sl_pattern, string:rh_release);
    if (!isnull(regex_results))
    {
      sl_num =  regex_results[1];
      parsed_release = "SL" + sl_num;
    }
  }
  else if ( egrep(pattern:centos_pattern, string:centos_release) )
  {
    regex_results = eregmatch(pattern:centos_pattern, string:centos_release);
    if (!isnull(regex_results))
    {
      centos_num =  regex_results[1];
      parsed_release = "CentOS-" + centos_num;
    }
  }
  else if ( egrep(pattern:centos_old_pattern, string:centos_release) )
  {
    regex_results = eregmatch(pattern:centos_old_pattern, string:centos_release);
    if (!isnull(regex_results))
    {
      centos_num =  regex_results[1];
      parsed_release = "CentOS-" + centos_num;
    }
  }
  else if ( egrep(pattern:euler_pattern, string:euler_release) )
  {
    regex_results = eregmatch(pattern:euler_pattern, string:euler_release);
    if (!isnull(regex_results))
    {
      euler_num =  regex_results[1];
      parsed_release = "EulerOS-" + euler_num;
    }
  }
  else if ( egrep(pattern:virtuozzo_pattern, string:virtuozzo_release) )
  {
    regex_results = eregmatch(pattern:virtuozzo_pattern, string:virtuozzo_release);
    if (!isnull(regex_results))
    {
      virtuozzo_num =  regex_results[1];
      parsed_release = "Virtuozzo-" + virtuozzo_num;
    }
  }

  if (isnull(parsed_release) || strlen(parsed_release) < 1) return RELEASE_MISSING;
  if (!isnull(release) && strlen(release) > 0)
  { 
    if (release == "ALA")
    {
      if (stridx(parsed_release, "ALA") != 0) return RELEASE_MISMATCH;
    }
    else
    {
      if (release != parsed_release) return RELEASE_MISMATCH;
    }
  }
  if (stridx(parsed_release, "ALA") == 0)
    rpms = get_kb_item("Host/AmazonLinux/rpm-list");
  else if ("MLOS" >< parsed_release)
    rpms = get_kb_item("Host/McAfeeLinux/rpm-list");
  else if ("XS" >< parsed_release)
    rpms = get_kb_item("Host/XenServer/rpm-list");
  else if ( "SUSE" >< parsed_release || "SLED" >< parsed_release || "SLES" >< parsed_release )
    rpms = get_kb_item("Host/SuSE/rpm-list");
  else if ("MDK" >< parsed_release)
    rpms = get_kb_item("Host/Mandrake/rpm-list");
  else if ("OVS" >< parsed_release )
    rpms = get_kb_item("Host/OracleVM/rpm-list");
  else if ("CentOS" >< parsed_release )
    rpms = get_kb_item("Host/CentOS/rpm-list");
  else if ("EulerOS" >< parsed_release )
    rpms = get_kb_item("Host/EulerOS/rpm-list");
  else if ("Virtuozzo" >< parsed_release )
    rpms = get_kb_item("Host/Virtuozzo/rpm-list");
  else
    rpms = get_kb_item("Host/RedHat/rpm-list");
  if (isnull(rpms) || strlen(rpms) < 1) return RPMS_MISSING;
  results["rpm-list"] = rpms;
  results["parsed_release"] = parsed_release;
  return results;
}

##
# Combs through the rpm list for the appropriate package from the
#              prefix or reference arguments, and compares the results,
#              adding them to the report and test values if appropriate.
#
# @param prefix prefix for which to generate packages to check for
# @param reference complete rpm string passed from plugin
# @param yank string of data to -= remove from version string and epoch
# @param epoch optional epoch time to compare rpms against
# @param cpu optional argument to specify that the target machine should
#              be a specific architecture and which that is.
# @param sp optional SuSE or RedHat service spack to specify the target
#              machine should be.
# @param allowmaj optional flag to cause rpm_cmp not to return RPM_EQUAL
#              if the major version (the 24 in 24.1.23) differs on rpm and
#              reference
# @param rpm_list optional copy of rpm-list to use instead of the one on
#              the remote system
#
# @remark Default behavior is to return RPM_EQUAL if the major versions
#              for rpm and reference are different, treating as entirely
#              different packages.
#              __pkg_tests and __rpm_report will be modified if a reference
#              is found and lesser version on machine, respectively.
#
# @return 1 if reference package found on machine of lesser version
#         0 if reference is for certain kernel files in some situations
#              or service pack mismatch or cpu mismatch
#              or unknown/inapplicable release
#              or missing rpm list
#              or package not found on target machine
#              or package found on target machine of >= versions than
#              reference
#              or package found on target machine of different major version
#              with allowmaj NULL or FALSE
##
function rpm_check(prefix, reference, yank, release, epoch, cpu, sp, allowmaj, rpm_list)
{
  local_var rh_sp, suse_sp, euler_sp, virtuozzo_sp, rpms, package, lines, e, my_rpm, ok;
  local_var my_cpu, my_reference, rpm_results;

  if ( "kernel-doc" >< reference ) return 0;

  if (get_kb_item("Host/uptrack-uname-r") && !get_kb_item("Host/uptrack-disable-file") && match(pattern:"kernel*", string:reference)) return 0;

  rh_sp = get_kb_item("Host/RedHat/minor_release");
  suse_sp = get_kb_item("Host/SuSE/patchlevel");
  euler_sp = get_kb_item("Host/EulerOS/sp");
  virtuozzo_sp = get_kb_item("Host/Virtuozzo/minor_release");

  # Change this when other distros use SP too
  if ( !isnull(sp) && (
       ( !isnull(euler_sp) && sp != int(euler_sp) ) ||
       ( !isnull(suse_sp) && sp != int(suse_sp) ) ||
       ( !isnull(rh_sp) && sp != int(rh_sp) ) ||
       ( !isnull(virtuozzo_sp) && sp != int(virtuozzo_sp) )
  ) )
    return 0;

  if ( ! isnull(cpu) )
  {
    my_cpu = get_kb_item("Host/cpu");
    # my_cpu returns a newline
    # 1270164212 1 Host/cpu=x86_64\n
    my_cpu = chomp(my_cpu);

    if ( my_cpu != cpu )
    {
      if (my_cpu =~ "i[3-6]86" && cpu =~ "i[3-6]86")
      {
        if (int(substr(my_cpu, 1)) < int(substr(cpu, 1))) return 0;
      }
      else return 0;
    }
  }

  rpm_results = _check_release_strings(release:release);

  if ( typeof(rpm_results) == "int" || isnull(rpm_results) ) return 0;
  if (isnull(rpm_results["rpm-list"]))
    return 0;
  else
    rpms = rpm_results["rpm-list"];

  if (rpm_list && strlen(rpm_list) > 0)
    rpms = rpm_list;

  if ( reference =~ "^(vz)?kernel-" ) rpms = fixup_rpm_list(rpms);

  if ( prefix )
  {
    if ( "kernel-" == prefix )
      package = egrep(pattern:"^kernel-([0-9]|unsupported|source|smp|hugemem|doc|BOOT)", string:rpms);
    else
      package = egrep(pattern:"^" + prefix + "([0-9]|devel|libs|utils|common|core|client|server)", string:rpms);
  }
  else
  {
    my_rpm = parse_rpm_name(rpm:reference, yank:yank);
    package = egrep(pattern:"^" + my_rpm["name"] + "-[0-9]", string:rpms);
  }
  if (!package) return 0;

  lines = split(package, sep:'\n', keep:0);
  foreach package (lines)
  {
    e =  rpm_cmp(rpm:package, reference:reference, yank:yank, epoch:epoch, allowmaj:allowmaj);
    if (e != RPM_MISMATCH)
    {
      pkg_tests_add(package);
    }
    else
    {
      my_rpm = parse_rpm_name(rpm:package, yank:yank);
      my_reference = parse_rpm_name(rpm:reference, yank:yank);
      if (my_rpm["name"] == my_reference["name"])
      {
        pkg_tests_add(package);
      }
    }
    if ( e == RPM_OLDER)
    {
      rpm_report_add(package:package, reference:reference);
      if ( "kernel-" >!< reference )
        return 1;
    }
    else if (e != RPM_MISMATCH)
      ok = 1;
  }


  if ( "kernel-" >!< reference )
    return 0;
  else
  {
    if ( ok )
    {
      return 0;
    }
    else
      return 1;
  }
}

##
# Checks if a specific rpm string exists within a system's rpm list
#
# @param rpm rpm name (ie: python-devel-), anchored to left
# @param release OS release release number (ie: RHEL6)
# @param rpm_list optional copy of rpm-list to use instead of the one on
#              the remote system
#
# @remark A complete rpm is not required, it is fed into a
#              start anchored regex, partial packages allowed
#
# @return 1 if rpm installed and Host OS release == release
#         0 otherwise
##
function rpm_exists(rpm, release, rpm_list)
{
  local_var rpms, rpm_results;

  if (get_kb_item("Host/uptrack-uname-r") && !get_kb_item("Host/uptrack-disable-file") && match(pattern:"kernel*", string:rpm)) return 0;

  rpm_results = _check_release_strings(release:release);
  if ( typeof(rpm_results) == "int" || isnull(rpm_results) ) return 0;

  if (isnull(rpm_results["rpm-list"]))
    return 0;
  else
    rpms = rpm_results["rpm-list"];

  if (rpm_list && strlen(rpm_list) > 0)
    rpms = rpm_list;

  if ( egrep(pattern:"^" + rpm, string:rpms) )
    return 1;
  else
    return 0;
}


# RedHat-specific functions section

##
# Returns text explaining the package method of detection, issues
# behind it, and how to properly set up 'yum updateinfo list security
# updates'.
#
# @return caveat block
##
function redhat_report_package_caveat()
{
  local_var caveat;
  caveat =
"NOTE: The vulnerability information above was derived by checking the
package versions of the affected packages from this advisory. This
scan is unable to rely on Red Hat's own security checks, which
consider channels and products in their vulnerability determinations.";
  return caveat;
}

##
# Returns text explaining the yum-updateinfo method of detection,
# and which RHSA to apply to resolve the issue.
#
# @return caveat block
##
function redhat_report_yum_caveat(rhsa)
{
  local_var caveat;
  if (isnull(rhsa)) rhsa = 'the necessary updates';
  caveat =
"NOTE: The vulnerability information above was derived from the use of
the 'yum updateinfo list security updates' command to determine which
Red Hat security advisories apply to this system. Apply
" + rhsa + " to resolve this vulnerability.
";

  return caveat;
}

##
# Checks which packages in yum-updateinfo relate to the RHSA,
# determines which fix packages are associated with that RHSA,
# determines which installed packages are associate with those fix
# packages, and compiles the data together to be returned as a string.
#
# @param rhsa string to determine what RHSA the vulnerability applies
#
# @return NULL if yum_updateinfo isn't present or
#                 rhsa is NULL or empty or
#                 rhsa is not present in yum_updateinfo or
#                 rpm-list is not present
#         string containing package reports plus descriptive caveat
#                otherwise
#
##

function redhat_generate_yum_updateinfo_report(rhsa)
{
  local_var yum_updateinfo, rhsa_pattern, rhsa_lines, rhsa_line;
  local_var fix_packages, fix_to_installed_array;
  local_var rpms, fixup_flag, fixed_rpm, package_name, fixed_parsed;
  local_var rpm_list_matches, rpm_list_lines, rpm_line, rpm_line_parsed;
  local_var installed_rpm, rpm_report, fixed_rpm_trimmed;
  fix_to_installed_array = make_array();
  yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
  rpms = get_kb_item("Host/RedHat/rpm-list");
  if (isnull(rhsa) || strlen(rhsa) < 1) return NULL;
  if (isnull(yum_updateinfo) || strlen(yum_updateinfo) < 1) return NULL;
  if (isnull(rpms) || strlen(rpms) < 1) return NULL;
  if (rhsa >!< yum_updateinfo) return NULL;
  rhsa_pattern = "^" + rhsa + "\s+[a-zA-Z]+/Sec\.\s+(.*)$";
  rhsa_lines = egrep(pattern:rhsa_pattern, string:yum_updateinfo, icase:TRUE);
  rhsa_lines = split(rhsa_lines, sep:'\n', keep:0);
  foreach rhsa_line (rhsa_lines) {
    fixed_rpm = eregmatch(pattern:rhsa_pattern, string:rhsa_line, icase:TRUE);
    if (!isnull(fixed_rpm)) {
      fixed_rpm = fixed_rpm[1];

      # These yum-updateinfo lines always include a .x86_64 or .noarch
      # or .x686 that we have traditionally trimmed out
      fixed_rpm_trimmed = ereg_replace(string:fixed_rpm, pattern:"\.[^\.]+$", replace:'');
      if ( !isnull(fixed_rpm_trimmed) ) {
        fixed_rpm = fixed_rpm_trimmed;
      }

      fixed_parsed = parse_rpm_name(rpm:fixed_rpm);
      package_name = fixed_parsed["name"];
    
      # Fixup if necessary
      if ( package_name =~ "^kernel-" && isnull(fixup_flag)) {
        rpms = fixup_rpm_list(rpms);
        fixup_flag = 1;
      }

      rpm_list_lines = egrep(pattern:"^" + package_name + "-[0-9]", string:rpms);

      rpm_list_matches = split(rpm_list_lines, sep:'\n', keep:0);
      foreach rpm_line (rpm_list_matches)
      {
        rpm_line_parsed = parse_rpm_name(rpm:rpm_line);
        if (rpm_line_parsed["name"] == package_name)
        {
          fix_to_installed_array[fixed_rpm] = rpm_line;
        }
      }
    }
  }
  if (keys(fix_to_installed_array)) {
    foreach fixed_rpm (sort(keys(fix_to_installed_array))) {
      rpm_report_add(package:fix_to_installed_array[fixed_rpm], reference:fixed_rpm);
    }
  }
  rpm_report = rpm_report_get();
  # This should never happen. We are forcing it to happen as a safety precaution
  # to avoid weird NULL output in the report text.
  if (isnull(rpm_report)) rpm_report = 'Unable to determine installed/fixed package versions for\n' + rhsa + ', even though it is reported by Red Hat as being\nunpatched.\n\n';
  return rpm_report + redhat_report_yum_caveat(rhsa:rhsa);
}
