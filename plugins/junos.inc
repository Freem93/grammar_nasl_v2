#TRUSTED 98fa86413fabe8228bce682290f8db97d5a20b8e3590cf9bc0d276a2eb689d34a5342f079a407fcbe96de04fbfab5eb251f7cb4113afcff5d8bcaa8bff6798409d6210318e88e58b6f978cacd1e216bec0e16f9a4948c03926e8e34a515f25954664b3e113d9c20a82e049b432e87e9324da0d9f760a2833a06daf7175dac128f77112e9ca845abf3629f032de49273a4824caab95a62da9b05432c783867d2b098bc252ca35edaa487832281d42571a6321f92fd12e8f76b62c1c018fb61a6ff1fa93fc95bcef7441c72893c2e9ebe29b2ae85af1306d9c448fd41c73a09f4b195d69a453043ec15775c3b3df0d087a1379bb05452f6fc4f7607fc340e4c2b9ef3f94e318ca1cc707ed59323f57268fb812c359165cb07a89fd449a9851558abf037dbe16483bee13637afdb480d78167c7872d2c10282fe62ce371e3ddf0ac31bae4aebe3d0c76646f89756ecde7873860992bebe69a2d91b5eec2e446454ab137d585da5330cadf23e2092cc9a9808f564241b4ec78546950507a53520a9383bab40af328c271a105e02bf88f27a090f03fb20fef877fd5b3aefeb636662f8e5c777568f9415e50101a90f68a42985f1821ccdf032b27e168b543ca3cca76c1e649ec9f6f04c38ff6f851faf858020b69ebeeff93796530d0a2825f13a8d44b1da72245e393ab4b74ddc64c509a72c10a14dae6c6fb25af93c198841795c4
###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
# This include file provides functions used for Junos patch auditing
#
# junos.inc
#
# Revision: 1.15
###

include("global_settings.inc");

# Some constants used with the 'flags' parameter of check_model()
E_SERIES   = 1 << 0;
EX_SERIES  = 1 << 1;
G_SERIES   = 1 << 2;
IC_SERIES  = 1 << 3;
J_SERIES   = 1 << 4;
M_SERIES   = 1 << 5;
MX_SERIES  = 1 << 6;
SRX_SERIES = 1 << 7;
T_SERIES   = 1 << 8;
LN_SERIES  = 1 << 9;
JCS_SERIES = 1 << 10;
PTX_SERIES = 1 << 11;
QFX_SERIES = 1 << 12;
F_SERIES   = 1 << 13;
ACX_SERIES = 1 << 14;
# It appears the only series that aren't routers are :
# EX / QFX (switches)
# IC (access control)
# JCS (control system)
ALL_ROUTERS = ACX_SERIES | E_SERIES | F_SERIES | G_SERIES | J_SERIES | M_SERIES | MX_SERIES | PTX_SERIES | SRX_SERIES | T_SERIES | LN_SERIES;
# BX series appears to be a solution comprised of M series, MX series, and JUNOScope software

##
# Compares two dates in the format YYYY-MM-dd
#
# @anonparam a date to compare
# @anonparam b date to compare
# @return -1 if a < b
#          0 if a == b
#          1 if a > b
##
function compare_build_dates()
{
  local_var a, b, i;
  a = _FCT_ANON_ARGS[0];
  b = _FCT_ANON_ARGS[1];

  if (isnull(a))
  {
    err_print('compare_build_dates(): missing first argument');
    return NULL;
  }
  if (isnull(b))
  {
    err_print('compare_build_dates(): missing second argument');
    return NULL;
  }

  a = split(a, sep:'-', keep:FALSE);
  b = split(b, sep:'-', keep:FALSE);

  for (i = 0; i < 3; i++)
  {
    if (int(a[i]) < int(b[i]))
      return -1;
    else if (int(a[i]) > int(b[i]))
      return 1;
  }

  return 0;
}

##
# Checks if the given model is a member of one of the series denoted by 'flags'
#
# @param model        model number to check
# @param flags        a bitmask of *_SERIES flags
# @param exit_on_fail exits if 'model' is not a member of the 'flags' series (instead of returning)
#
# @return TRUE if 'model' is a member of any of the series denoted by 'flags',
#         FALSE otherwise
##
function check_model(model, flags, exit_on_fail)
{
  if (isnull(model))
  {
    err_print('check_model(): missing argument "model"');
    return NULL;
  }
  if (isnull(flags))
  {
    err_print('check_model(): missing argument "flags"');
    return NULL;
  }

  if (flags & E_SERIES && model =~ '^E(RX)?[0-9]+')  # E-series begin with either E, or ERX. but not EX.
    return TRUE;
  else if (flags & EX_SERIES && model =~ '^EX[0-9]+')
    return TRUE;
  else if (flags & G_SERIES && model =~ '^G[0-9]+')
    return TRUE;
  else if (flags & IC_SERIES && model =~ '^IC[0-9]+')
    return TRUE;
  else if (flags & J_SERIES && model =~ '^J[0-9]+')
    return TRUE;
  else if (flags & JCS_SERIES && model =~ '^JCS[0-9]+')
    return TRUE;
  else if (flags & LN_SERIES && model =~ '^LN[0-9]+')
    return TRUE;
  else if (flags & M_SERIES && model =~ '^M[0-9]+')
    return TRUE;
  else if (flags & MX_SERIES && model =~ '^v?MX[0-9]+')
    return TRUE;
  else if (flags & PTX_SERIES && model =~ '^PTX[0-9]+')
    return TRUE;
  else if (flags & QFX_SERIES && model =~ '^QFX[0-9]+')
    return TRUE;
  else if (flags & SRX_SERIES && (model =~ '^v?SRX[0-9]+' || model =~ '^firefly-perimeter'))
    return TRUE;
  else if (flags & T_SERIES && model =~ '^T[0-9]+')
    return TRUE;
  else if (flags & ACX_SERIES && model =~ '^ACX[0-9]+')
    return TRUE;

  if (exit_on_fail)
    exit(0, 'Model ' + model + ' is not affected.');
  else
    return FALSE;
}

##
# Compares two Junos version numbers.  This function assumes that the only
# valid release types are A, B, I, F, R, and S
#
# This function will return 0 if either 'a' or 'b' are interim releases,
# either 'a' or 'b' are not in the expected format (x.yRr.b, .b is optional),
# or the major release numbers of 'a' and 'b' are different
#
# @anonparam a first version to compare
# @anonparam b second version to compare
#
# @return -1 if 'a' is less than 'b'
#          0 if 'a' is equal to 'b'
#          1 if 'a' is greater than 'b'
##
function _junos_base_ver_compare()
{
  local_var a, b, match, a_major, b_major, a_type, b_type, a_rev, b_rev, a_build, b_build;
  a = _FCT_ANON_ARGS[0];
  b = _FCT_ANON_ARGS[1];

  # http://kb.juniper.net/InfoCenter/index?page=content&id=KB1868
  # e.g. 11.1R3.4
  # 11.1 - major version number
  # R - release type
  # 3 - revision
  # 4 - build (optional)
  match = eregmatch(string:a, pattern:'^([0-9]+\\.[0-9]+)([A-Z])([0-9]+)(\\.([0-9]+))?$');
  if (isnull(match))
  {
    err_print('_junos_base_ver_compare(): Error parsing version : ' + a);
    return 0;
  }
  a_major = match[1];
  a_type = ord(match[2]);
  a_rev = int(match[3]);
  a_build = int(match[5]);

  match = eregmatch(string:b, pattern:'^([0-9]+\\.[0-9]+)([A-Z])([0-9]+)(\\.([0-9]+))?$');
  if (isnull(match))
  {
    err_print('_junos_base_ver_compare(): Error parsing version : ' + b);
    return 0;
  }
  b_major = match[1];
  b_type = ord(match[2]);
  b_rev = int(match[3]);
  b_build = int(match[5]);

  # different major versions get supported differently, only like releases can be compared
  if (a_major != b_major)
    return 0;

  # Juniper says if an interim release is being used, there's no reliable way to
  # tell if it's missing security updates
  if (a_type == ord('I') || b_type == ord('I')) return 0;

  # If the types don't match and release types 'R' and 'S' are not being compared
  if (a_type != b_type && !(a_type >= ord('R') && b_type >= ord('R')))
  {
    # explicitly check if alpha vs beta is being compared
    if (a_type == ord('A') && b_type == ord('B')) return -1;
    if (a_type == ord('B') && b_type == ord('A')) return 1;

    # A (alpha) and B (beta) are always < F, R and S (feature velocity, release, security)
    if (a_type <= ord('B') && b_type >= ord('F')) return -1;
    if (a_type >= ord('F') && b_type <= ord('B')) return 1;

    # If we've gotten this far, one of a_type and b_type is F and the other is R or S
    # They can't be directly compared
    return 0;
  }

  # we should only get this far if the release types are the same,
  # or release types R and S are being compared.  For the latter
  # scenario, Juniper says the 'R' and 'S' can be ignored with
  # one exception (see below)
  if (a_rev < b_rev) return -1;
  if (a_rev > b_rev) return 1;
  if (a_build < b_build) return -1;
  if (a_build > b_build) return 1;

  # Juniper says if 'R' and 'S' versions are being compared and the major version,
  # revision, and build are identical, the 'S' version is more current
  if (a_type < b_type) return -1;
  if (a_type > b_type) return 1;

  return 0;
}

##
# Compares two Junos Space version numbers.  This function assumes that the only
# valid release types are R and P
#
# This function will return 0 if the versions are the same, and expects the
# versions to be in the format x.x[RP]x.x with [RP]x.x as optional.
#
# @param ver (first) version to compare
# @param fix (second) fixed version to compare
#
# @return -1 if 'a' is less than 'b'
#          0 if 'a' is equal to 'b'
#          1 if 'a' is greater than 'b'
##
function _junos_space_ver_compare(ver, fix)
{
  local_var match, v_major, f_major, v_minor, f_minor, v_type, f_type;
  local_var v_rev, f_rev, v_build, f_build;

  # http://kb.juniper.net/InfoCenter/index?page=content&id=KB1868
  # e.g. 11.1R3.4
  # 11.1 - major version number
  # R - release type
  # 3 - revision
  # 4 - build (optional)
  match = eregmatch(string:ver, pattern:'^([0-9]+)\\.([0-9]+)(([A-Z])([0-9]+)(\\.([0-9]+))?)?$');
  if (isnull(match))
  {
    err_print('_junos_space_ver_compare(): Error parsing version : ' + ver);
    return 0;
  }
  v_major = match[1];
  v_minor = match[2];
  if (!isnull(match[4]))
    v_type = ord(match[4]);
  v_rev = int(match[5]);
  v_build = int(match[7]);

  if (v_type && (v_type != ord('R') && v_type != ord('P')))
  {
    err_print('check_junos_space(): Error invalid release type: ' + v_type);
    return 0;
  }

  match = eregmatch(string:fix, pattern:'^([0-9]+)\\.([0-9]+)(([A-Z])([0-9]+)(\\.([0-9]+))?)?$');
  if (isnull(match))
  {
    err_print('_junos_space_ver_compare(): Error parsing version : ' + fix);
    return 0;
  }
  f_major = match[1];
  f_minor = match[2];
  if (!isnull(match[4]))
    f_type = ord(match[4]);
  f_rev = int(match[5]);
  f_build = int(match[7]);

  if (f_type && (f_type != ord('R') && f_type != ord('P')))
  {
    err_print('check_junos_space(): Error invalid release type: ' + f_type);
    return 0;
  }

  # With Junos Space major versions can be compared
  if (v_major < f_major) return -1;
  if (v_major > f_major) return 1;
  if (v_minor < f_minor) return -1;
  if (v_minor > f_minor) return 1;

  # Junos Space only has 'R' and 'P' types.
  # In most cases we will rather want to compare the rev and build
  if (v_rev < f_rev) return -1;
  if (v_rev > f_rev) return 1;
  if (v_build < f_build) return -1;
  if (v_build > f_build) return 1;

  # If we do have a equal Rev and Build then
  # 'P' > 'R'
  if (v_type == ord('R') && f_type == ord('P')) return -1;
  if (v_type == ord('P') && f_type == ord('R')) return 1;

  return 0;
}

##
# Compares two Junos special release version numbers
#
# This function assumes all versions will be in the format:
#
# 10.4X24
#
# Everything up to and including the X and the following numbers
# should match, and everything after should be compared.  The
# numbers are compared left to right. So the following two numbers
# would not be compared:
#
# 10.4X24
# 10.4X25.8
#
# The following two would be compared:
#
# 11.4X27.20
# 11.4X27.37
#
# This will be treated as comparing .20 to .37.  In other words, it
# makes the (perhaps incorrect) assumption that a given release train
# (for example, a 11.4X27 release) does not have multiple branches
# containing multiple fixes.
#
# @anonparam a first version to compare
# @anonparam b second version to compare
#
# @return -1 if 'a' is less than 'b'
#          0 if 'a' is equal to 'b'
#          1 if 'a' is greater than 'b'
##
function _junos_special_ver_compare()
{
  local_var a, b, a_match, b_match, a_release, b_release, a_train, b_train;
  a = _FCT_ANON_ARGS[0];
  b = _FCT_ANON_ARGS[1];

  a_match = eregmatch(string:a, pattern:"^([\d.]+X\d+)\.(\d+)");
  if (isnull(a_match))
    exit(1, 'Error parsing Junos version : ' + a);

  b_match = eregmatch(string:b, pattern:"^([\d.]+X\d+)\.(\d+)");
  if (isnull(b_match))
    exit(1, 'Error parsing Junos version : ' + b);

  a_train = a_match[1];
  a_release = a_match[2];
  b_train = b_match[1];
  b_release = b_match[2];

  # sanity checking - the parts of each version that are stripped away should match
  if (a_train != b_train)
    return NULL;

  if (int(a_release) < int(b_release))
    return -1;
  else if (int(a_release) > int(b_release))
    return 1;

  return 0;
}

##
# Compares two Junos X version numbers.
#
# Regarding 12.1X44-D10, this document says:
#   Junos 12.1 is the latest Junos release that includes security features and is
#   considered a stable release with core functionality; hence was selected as the baseline
#   for X44.
#   D10 denotes the specific release number for the X44 release train, and will be
#   incremented by 5 for maintenance releases, for example D15, D20, and so on.
#
# This function assumes all Junos X versions will be in the format:
#
# 12.2X50-D41.1
#
# In other words, everything up to and including the D should match, and
# everything after should be compared
#
# @anonparam a first version to compare
# @anonparam b second version to compare
#
# @return -1 if 'a' is less than 'b'
#          0 if 'a' is equal to 'b'
#          1 if 'a' is greater than 'b'
##
function _junos_x_ver_compare()
{
  local_var a, b, idx, a_train, b_train, a_release, b_release, i;
  a = _FCT_ANON_ARGS[0];
  b = _FCT_ANON_ARGS[1];

  # get the release number for each version.
  # for 12.2X50-D41.1, this means extracting 41.1
  idx = stridx(a, '-D');
  if (idx == -1)
    exit(1, 'Error parsing Junos version : ' + a);

  a_train = substr(a, 0, idx);
  a_release = substr(a, idx + 2);

  idx = stridx(b, '-D');
  if (idx == -1)
    exit(1, 'Error parsing Junos version : ' + b);

  b_train = substr(b, 0, idx);
  b_release = substr(b, idx + 2);

  # sanity checking - the parts of each version that are stripped away should match
  if (a_train != b_train)
    exit(1, 'Error comparing Junos versions ' + a + ' and ' + b);

  a_release = split(a_release, sep:'.', keep:FALSE);
  b_release = split(b_release, sep:'.', keep:FALSE);

  for (i = 0; i < max_index(a_release) || i < max_index(b_release); i++)
  {
    if (int(a_release[i]) < int(b_release[i]))
      return -1;
    else if (int(a_release[i]) > int(b_release[i]))
      return 1;
  }

  return 0;
}

##
# Compares two Junos version numbers including number which ends in -S.
#
# This function assumes all Junos -S versions will be in the format:
#
# 12.2R50-S41.1
#
# @anonparam a first version to compare
# @anonparam b second version to compare
#
# @return -1 if 'a' is less than 'b'
#          0 if 'a' is equal to 'b'
#          1 if 'a' is greater than 'b'
##
function _junos_ver_compare()
{
  local_var a, b, idx, a_train, b_train, a_release, b_release, i;
  a = _FCT_ANON_ARGS[0];
  b = _FCT_ANON_ARGS[1];

  # quick exit
  if (a == b) return 0;

  # get the release number for each version.
  # for 12.2S50-S41.1, this means extracting 41.1
  idx = stridx(a, '-S');
  if (idx == -1)
  {
    a_train = a;
    a_release = NULL;
  }
  else
  {
    a_train = substr(a, 0, idx-1);
    a_release = substr(a, idx + 2);
  }

  idx = stridx(b, '-S');
  if (idx == -1)
  {
    b_train = b;
    b_release = NULL;
  }
  else
  {
    b_train = substr(b, 0, idx-1);
    b_release = substr(b, idx + 2);
  }

  # if a_train != b_train then just compare them and return the result
   # or if the releases of both are null, then just compare the beginnings
  if ((a_train != b_train) || (isnull(a_release) && isnull(b_release))) return _junos_base_ver_compare(a_train, b_train);

  # check to see if either version has a null -S portion
  if (isnull(a_release)) return -1;
  if (isnull(b_release)) return 1;

  # a_train must == b_train at this point and neither version has a NULL -S portion
  # thus we compare releases
  a_release = split(a_release, sep:'.', keep:FALSE);
  b_release = split(b_release, sep:'.', keep:FALSE);

  for (i = 0; i < max_index(a_release) || i < max_index(b_release); i++)
  {
    if (int(a_release[i]) < int(b_release[i]))
      return -1;
    else if (int(a_release[i]) > int(b_release[i]))
      return 1;
  }

  return 0;
}

##
# Checks if a Junos version is out of date.
# Compares the given version to the relevant fixed version.
# If 'ver' doesn't have a corresponding fix in 'fixes', this function assumes it is not out-of-date.
#
# @param ver          version to check
# @param fixes        a hash of fixes. key = release, value = fix. e.g. 11.1 => 11.1S1
# @param exit_on_fail exits instead of returning NULL
#
# @return the appropriate fix if 'ver' is out-of-date,
#         NULL otherwise
##
function check_junos(ver, fixes, exit_on_fail)
{
  local_var match, feature, fix, junoss, junosx, release, report, series, special;
  if (isnull(ver))
  {
    err_print('check_junos(): missing argument "ver".');
    return NULL;
  }
  if (isnull(fixes))
  {
    err_print('check_junos(): missing argument "fixes".');
    return NULL;
  }

  junosx = FALSE;
  special = FALSE;
  feature = FALSE;

  # Try to extract the release (x.y) from the version.
  #
  # X releases look different than other versions
  # (e.g., 12.2X50-D41.1 versus 10.4R13)
  #
  # there is a third kind of version that looks different. i think they're
  # called "special releases" but there may be a different, official term
  # (e.g., 11.4X27 or 12.1X44)
  if (match = eregmatch(string:ver, pattern:"^([0-9.]+X[0-9.]+)-"))
    junosx = TRUE;
  else if (match = eregmatch(string:ver, pattern:"^([0-9.]+X)[0-9.]+$"))
    special = TRUE;
  else if (match = eregmatch(string:ver, pattern:"^([0-9.]+F)[0-9.]+$"))
    feature = TRUE;
  else
    match = eregmatch(string:ver, pattern:"^([0-9.]+)([A-Z])+");
  # display("junosx:", junosx, "; special:", special, " feature:", feature, '\n');
  # display("release:", match[1], " series:", match[2], '\n');
  if (isnull(match))
  {
    if (exit_on_fail)
      exit(1, 'check_junos(): error parsing version : ' + ver);

    err_print('check_junos(): error parsing version : ' + ver);
    return NULL;
  }
  else
  {
    release = match[1];
    series = match[2];
  }

  # If the caller says there's no fix for a given release, we're going to assume it's not vulnerable
  if (!isnull(fixes[release + series]))
  {
    fix = fixes[release + series];
  }
  else
  {
    fix = fixes[release];
  }
  if (isnull(fix))
  {
    if (exit_on_fail)
      exit(0, 'Junos ' + ver + ' is not affected.');
    else
      return NULL;
  }
  if (
    (junosx && _junos_x_ver_compare(ver, fix) < 0) ||
    (special && _junos_special_ver_compare(ver, fix) < 0) ||
    (!junosx && !special && !junoss && _junos_ver_compare(ver, fix) < 0)
  )
  {
    return fix;
  }
  else if (exit_on_fail)
    exit(0, 'Junos ' + ver + ' is not affected.');
  else
    return NULL;
}

##
# Checks if a Junos Space version is out of date.
# Compares the given version to the relevant fixed version.
# Will either exit or print report.
# Specifically this will flag previous versions.
#
# @param ver        The version to check
# @param fix        The fixed version
# @param severity   The severity rating for reporting
# @param min        The minimum vulnerable version
# @param xss        A boolean value to determine if the XSS kb item has to be set
# @param xsrf       A boolean value to determine if the XSRF kb item has to be set
# @param sqli       A boolean value to determine if the SQLI kb item has to be set
#
# @return NULL if there was an error.
##
function check_junos_space(ver, fix, severity, min, xss, xsrf, sqli)
{
  if (isnull(ver))
  {
    err_print('check_junos_space(): missing argument "ver"');
    return NULL;
  }
  if (isnull(fix))
  {
    err_print('check_junos_space(): missing argument "fix"');
    return NULL;
  }
  if (isnull(severity))
  {
    err_print('check_junos_space(): missing argument "severity"');
    return NULL;
  }

  if (min && _junos_space_ver_compare(ver:ver, fix:min) < 0)
    exit(0, 'Junos Space ' + ver + ' is not affected.');

  if (_junos_space_ver_compare(ver:ver, fix:fix) < 0)
  {
    if (xss)
      set_kb_item(name:'www/0/XSS', value:TRUE);
    if (xsrf)
      set_kb_item(name:'www/0/XSRF', value:TRUE);
    if (sqli)
      set_kb_item(name:'www/0/SQLInjection', value:TRUE);
    security_report_v4(port:0, extra:get_report(ver:ver, fix:fix), severity:severity);
    exit(0);
  }
  else
    exit(0, 'Junos Space ' + ver + ' is not affected.');
}

##
# Generates plugin output for on out-of-date Junos install
#
# @param model    model number of the Junos device (optional)
# @param ver      currently installed Junos version
# @param fix      version to upgrade to
#
# @return plugin output
##
function get_report(model, ver, fix)
{
  local_var report;
  report = '';

  if (!isnull(model))
    report += '\n  Model             : ' + model;

  report +=
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix + '\n';

  return report;
}

##
# Parses the branch of ver
#
# @param string ver  Junos version
#
# @return branch of specified version (e.g. 14.2R6 returns 14.2R, 12.1X46-D45 returns 12.1X46, etc.)
#         NULL if invalid version
##
function junos_ver_branch(ver)
{
  local_var keep, separator, branch;

  if (isnull(ver) || typeof(ver) !~ '^(string|data)$')
  {
    err_print("junos_ver_branch: 'ver' must be specified and a string");
    exit(1);
  }

  keep = TRUE;
  foreach separator (make_list("R", "F", "-", "S")) # '-' should be second to last and 'S' last
  {
    if (separator >< ver)
    {
      if (separator == "-") keep = FALSE;
      branch = split(ver, sep:separator, keep:keep);
      return branch[0];
    }
  }
}

##
# Compare detected version with fixed versions when a advisory has multiple fixed versions.
#
# @param string ver    Junos version
# @param array  fixes  nested array of advisories using 'CVEs' and 'Fixed Versions' as keys
#
# @remark This is mainly to be used for Juniper advisories covering multiple OpenSSL versions
#
# @return report including CVE IDs associated with the fixed version if affected
#         NULL if not affected
##
function junos_multi_check_and_report(ver, fixes)
{
  local_var sep, cve_ids, ver_branch, required_keys, key, month;
  local_var fix_list, fix, fix_branch, cve_report, fix_report, report_cve_ids, report;

  if (isnull(ver) || typeof(ver) !~ '^(string|data)$')
  {
    err_print("junos_multi_check_and_report: 'ver' must be specified and a string");
    exit(1);
  }

  if (empty_or_null(fixes) || typeof(fixes) != 'array')
  {
    err_print("junos_multi_check_and_report: 'fixes' must be specified and a nested array");
    exit(1);
  }

  sep = ", ";
  cve_ids = make_nested_array();

  ver_branch = junos_ver_branch(ver:ver);
  if (isnull(ver_branch)) audit(AUDIT_FN_FAIL, "junos_ver_branch", "NULL");

  foreach month (keys(fixes))
  {
    required_keys = make_list("CVEs", "Fixed Versions");
    foreach key (required_keys)
    {
      if (isnull(fixes[month][key]) || typeof(fixes[month][key]) !~ '^(string|data)$')
      {
        err_print("junos_multi_check_and_report: '"+ month +"' is missing the '"+ key +"' key or not assigned a string");
        exit(1);
      }
    }
    fix_list = split(fixes[month]["Fixed Versions"], sep:sep, keep:FALSE);
    foreach fix (fix_list)
    {
      fix_branch = junos_ver_branch(ver:fix);
      if (isnull(fix_branch) || fix_branch != ver_branch) continue;
      if (!isnull(check_junos(ver:ver, fixes:make_array(fix_branch, fix))))
      {
        if (isnull(cve_ids[fix])) cve_ids[fix] = make_list();
        cve_ids[fix] = make_list(cve_ids[fix], split(fixes[month]["CVEs"], sep:sep, keep:FALSE));
      }
    }
  }
  if (empty(cve_ids)) return NULL;

  # Sort, dedup, and report CVE IDs 
  fix_report = make_list();
  foreach fix (keys(cve_ids))
  {
    fix_report = make_list(fix_report, fix);
    cve_report += '\n    ' + join(list_uniq(sort(cve_ids[fix])), sep:sep);
    if (len(cve_ids) == 1) break; # We don't append the fixed version if there is only one fix
    cve_report += ' (fixed in ' + fix + ')';
  }

  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed versions    : ' + join(sort(fix_report), sep:' / ') +
    '\n  CVEs fixed        : ' + cve_report +
    '\n';

  return report;
}
