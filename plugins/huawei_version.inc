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
# huawei_func.inc
# $Revision: 1.3 $
#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

### Constants ###
HV_VER_PATTERN = "V(\d+)R(\d+)(?:C(\d+))?(?:(\w+?)(\d+))?(?:(\w+?)(\d+))?";
HV_VER_SUFFIX_INDEXES = make_list(4, 6);

# Some of these are made up because I'm unaware of relative seniority.
# For example, I know SPH and HP come after SPC but I have no idea
# how L and LG relate. That said, I have not seen those kinds of
# comparisons arise thus far and if they do, this array can be
# modified.
HV_VER_SUFFIXES = make_array(
  "L", '1',
  "LG", '1',
  "LH", '1',
  "LS", '1',
  "SPC", '1',
  "SPH", '2',
  "HP", '2',
  "B", '1',
  "SP", '1');

### Check Types ###
HV_CHECK_LATER   = 1;
HV_CHECK_EQUAL   = 0;
HV_CHECK_EARLIER = -1;

##
# Parse a Huawei version number into something ver_compare can
# understand.
#
# @param  string version that match matches HV_VER_PATTERN
#
# @return string parse version consisting of digits separated by '.'
#         NULL on error
##
function huawei_parse_version(version)
{
  local_var match, index;
  local_var parsed_version;

  if (isnull(version)) version = _FCT_ANON_ARGS[0];
  if (isnull(version))
  {
    err_print("huawei_parse_version(): missing required arg 'version'");
    return NULL;
  }

  # Get all the components out of the version.
  match = eregmatch(string:version, pattern:HV_VER_PATTERN);

  # If we can't parse this, exit out with an error.
  if (isnull(match)) exit(1, "Failed to parse Huawei version " + version);

  # Add the straightforward numerical bits.
  parsed_version = match[1] + '.' + match[2];

  # Now translate the weird bits at the end.
  foreach index (HV_VER_SUFFIX_INDEXES)
  {
    if (!isnull(match[index]))
    {
      # If we don't know this suffix, exit with an error.
      if (isnull(HV_VER_SUFFIXES[match[index]]))
        exit(1, "Encountered unknown suffix '" + match[index] + "' while parsing " + version);

      parsed_version += '.' + HV_VER_SUFFIXES[match[index]] + '.' + match[index + 1];
    }
    else parsed_version += '.0.0';
  }

  # Based on looking at several advisories, it seems that the C
  # version should be looked at last since changing from SPC to SPH
  # appears to take precedence over the C version.
  # If there is no C(ustom) version, set it to 0.
  if (!isnull(match[3])) parsed_version += match[3];
  else parsed_version += '.0';

  return parsed_version;
}

##
# Compares two Huawei version strings.
# @param  string ver that match matches HV_VER_PATTERN
# @param  string ref that match matches HV_VER_PATTERN
# @return int    result of running ver_compare on parsed inputs.
##
function huawei_ver_compare(ver, ref)
{
  local_var func_name;
  local_var ver_parsed, ref_parsed;

  func_name = "huawei_ver_compare";

  # Input validation.
  if (isnull(ver))
  {
    err_print(func_name + "(): missing required arg 'ver'");
    return NULL;
  }

  if (isnull(ref))
  {
    err_print(func_name + "(): missing required arg 'ref'");
    return NULL;
  }

  # Check for equality since this is the easiest check.
  if (ver == ref) return 0;

  # Otherwise, parse the 2 versions.
  ver_parsed = huawei_parse_version(ver);
  ref_parsed = huawei_parse_version(ref);

  return ver_compare(ver:ver_parsed, fix:ref_parsed, strict:FALSE);
}

##
# Determines if a version is vulnerable.
#
# @param  string version to be checked
# @param  string vuln      known vuln version
# @param  string patchlist output of running display patch-information
#                          on the system
# @param  list patches     list of patches that address the issue
# @param  int  type        type of comparison that will be done to
#                          determine vulnerability. HV_CHECK_EQUAL means
#                          vuln and version must be equal.
#                          HV_CHECK_EARLIER flags version if equal to
#                          or earlier than vuln.
#                          HV_CHECK_LATER flags version if it's between
#                          vuln and fix.
#
# @return int            TRUE if vulnerable, FALSE otherwise.
#                        NULL on error.
##
function huawei_is_ver_vuln(version, patchlist, vuln, patches, type)
{
  local_var func_name,patch,verisvuln;

  func_name = 'huawei_is_ver_vuln';

  # Input Validation
  if (isnull(version))
  {
    err_print(func_name + "(): missing required arg 'version'");
    return NULL;
  }

  if (isnull(vuln))
  {
    err_print(func_name + "(): missing required arg 'vuln'");
    return NULL;
  }

  # Default Value
  if (isnull(type)) type = HV_CHECK_EQUAL;
  if (isnull(patches))
    patches = make_list();

  verisvuln = FALSE;

  if (type == HV_CHECK_EQUAL && version == vuln) verisvuln = TRUE;
  else if (type == HV_CHECK_EARLIER && huawei_ver_compare(ver:version, ref:vuln) <= 0)
    verisvuln = TRUE;
  else if (
    type == HV_CHECK_LATER &&
    huawei_ver_compare(ver:version, ref:vuln) >= 0 &&
    huawei_ver_compare(ver:version, ref:vuln) == -1
  ) verisvuln = TRUE;

  if(verisvuln)
  {
    foreach patch (patches)
    {
      # System is patched
      if(patch >< patchlist)
        return FALSE;
    }
  }
  return verisvuln;
}

##
# Checks is a Huawei device is vulnerable and reports as needed.
#
# @param  string model     Model of Huawei device.
# @param  string series    Series device belongs to.
# @param  string version   Firmware version of device.
# @param  list   reference List of refs. A ref is an array s.t.
#                          'series' key is a list of all affected
#                          series (as regex patterns) and 'checks'
#                          is a list of individual checks where each
#                          check is an array s.t. 'vuln' key contains
#                          vulnerable version, 'fix' contains fixed
#                          version(s), type' contains the type of
#                          check to perform.# and optionally 'patches'
#                          which contains a list of patches, that if
#                          applied to the vulnerable system will resolve
#                          the vulnerability (optional for backwards
#                          compat)
# @param  int    severity  Report severity to be passed to
#                          security_report_v4()
# @param  string patchlist OPTIONAL, output from running the command 
#                          'display patch-information' on the system 
#                          (optional for backwards compat)
# @param  bool   xss       OPTIONAL, if TRUE, sets XSS kb
# @param  bool   xsrf      OPTIONAL, if TRUE, sets XSRF kb
# @param  bool   sqli      OPTIONAL, if TRUE, sets SQLI kb
##
function huawei_check_and_report(model, series, version, patchlist, reference, severity, xss, xsrf, sqli)
{
  local_var func_name;
  local_var ref;
  local_var version_is_affected, series_is_affected;
  local_var affected_series, check;
  local_var fix, report;

  func_name = "huawei_check_and_report";

  # Input validation.
  if (isnull(model))
  {
    err_print(func_name + "(): missing required arg 'model'");
    exit(1);
  }

  if (isnull(series))
  {
    err_print(func_name + "(): missing required arg 'series'");
    exit(1);
  }

  if (isnull(version))
  {
    err_print(func_name + "(): missing required arg 'version'");
    exit(1);
  }

  if (isnull(reference))
  {
    err_print(func_name + "(): missing required arg 'reference'");
    exit(1);
  }

  if (isnull(severity))
  {
    err_print(func_name + "(): missing required arg 'severity'");
    exit(1);
  }

  if (typeof(reference) != 'array')
  {
    err_print(func_name + "(): arg 'reference' must be type 'list'");
    exit(1);
  }

  if (isnull(patchlist))
    patchlist = "";

  series_is_affected = FALSE;
  version_is_affected = FALSE;

  # Verify series.
  for (ref = 0; ref < len(reference); ref++)
  {
    foreach affected_series (reference[ref]['series'])
    {
      if (series =~ affected_series)
      {
        series_is_affected = TRUE;
        break;
      }
    }

    if (series_is_affected) break;
  }

  if (!series_is_affected) audit(AUDIT_DEVICE_NOT_VULN, model);

  # Check if version is affected.
  foreach check (reference[ref]['checks'])
  {
    if (huawei_is_ver_vuln(version:version, patchlist:patchlist, vuln:check['vuln'], patches:check['patches'], type:check['type']))
    {
      version_is_affected = TRUE;
      fix = check['fix'];
      break;
    }

    if (version_is_affected) break;
  }

  # Report or exit.
  if (version_is_affected)
  {
    # Add KB flag if needed.
    if (xss) set_kb_item(name:'www/0/XSS', value:TRUE);
    if (xsrf) set_kb_item(name:'www/0/XSRF', value:TRUE);
    if (sqli) set_kb_item(name:'www/0/SQLInjection', value:TRUE);

    report =
      '\n  Model            : ' + model +
      '\n  Firmware version : ' + version +
      '\n  Fixed version    : ' + fix +
      '\n';
    security_report_v4(port:0, extra:report, severity:severity);
    exit(0);
  }
  else audit(AUDIT_DEVICE_NOT_VULN, model, version);
  return 0;
}
