#------------------------------------------------------------------------------
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# emc_documentum.inc
#
# $Revision: 1.1 $
#
# @include audit.inc
# @include global_settings.inc
# @include misc_func.inc
###
#

include("install_func.inc");

### Debug Flag ###
IF_VERBOSE_ERRORS = TRUE;

# Return Codes
# Negative values are conditions that should not occur at run-time
# Positive values can occur at run-time and should be handled
# gracefully.
DOC_BAD_PATCH    = 1;   # Unexpected Patch name.
DOC_OK           = 0;   # Successful return.
DOC_ERROR        = -1;  # General/Unknown/Upstream error.
DOC_MISSING_ARG  = -2;  # Missing argument to function.
DOC_ARG_BAD_TYPE = -3;  # Function argument is the wrong type.

# Error Templates
_DOC_ERROR_TEMPLATE = make_list(1, "%s(): Unknown or upstream error occurred.", DOC_ERROR);
_DOC_MISSING_ARG_TEMPLATE = make_list(2, "%s(): missing required argument '%s'.", DOC_MISSING_ARG);
_DOC_ARG_BAD_TYPE_TEMPLATE = make_list(3, "%s(): '%s' arg must be type '%s'.", DOC_ARG_BAD_TYPE);

##
# Application Name
##
global_var DOC_APP_NAME;
DOC_APP_NAME = "EMC Documentum Content Server";

##
# Documentum Patch Format
##
global_var _PATCH_PATTERN;
_PATCH_PATTERN = "^(\d+\.\d+)(?:\s*SP(\d+))?(?:\s*P(\d+))?$";

##
# No minimum version for check
##
global_var DOC_NO_MIN;
DOC_NO_MIN = '0';

##
# Hotfix Modifier to be appended to fix name.
##
global_var DOC_HOTFIX;
DOC_HOTFIX = " (Hotfix)";

##
# Generate an alternate version number to use internally from patch.
#
# @param  patch patch display version from patch-info.xml
# @return [list] ret st. ret[0] is the return code
#                        ret[1] is the alternate version
##
function _make_alt_version(patch)
{
  local_var func_name, args;
  local_var match;
  local_var alt_version;

  func_name = "make_alt_version";

  # Accept argument anonymously.
  if (isnull(patch)) patch = _FCT_ANON_ARGS[0];

  # Input validation.
  if (isnull(patch))
  {
    args = make_list(func_name, 'patch');
    return make_list(return_error(_DOC_MISSING_ARG_TEMPLATE, args));
  }

  # Parse patch, it should match the pattern below or we
  # return an error.
  match = eregmatch(string:patch, pattern:_PATCH_PATTERN, icase:TRUE);
  if (isnull(match)) return make_list(DOC_BAD_PATCH);

  alt_version = match[1];

  if (!isnull(match[2])) alt_version += '.' + int(match[2]);
  else alt_version += '.0';

  if (!isnull(match[3])) alt_version += '.' + int(match[3]);

  return make_list(DOC_OK, alt_version);
}

##
# Checks if an install of EMC Documentum Content Server is vulnerable.
#
# @param  install  valid install returned by get_*() in install_func.inc
# @param  fixes    list of fixes s.t. fix[0] is the fix
#                                     fix[1] is min version fix applies to (OPTIONAL)
# @param  severity report severity
# @param  xss      flags vuln as XSS
# @param  xsrf     flags vuln as XSRF
# @param  sqli     flags vuln as SQLInjection
#
# @remark          If fix[0] for any element in fixes includes DOC_HOTFIX then
#                  installs of the same version as fix[0] will be flagged on
#                  paranoid scans.
# @remark          This function either reports or audits, it returns nothing.
##
function documentum_check_and_report(install, fixes, severity, xss, xsrf, sqli)
{
  local_var func_name, args;
  local_var fix, fix_version, alt_version, fix_branch, min;
  local_var comparison, vuln;
  local_var report;

  func_name = "documentum_check_and_report";

  # Input Validation
  if (isnull(install))
  {
    args = make_list(func_name, 'install');
    return return_error(_DOC_MISSING_ARG_TEMPLATE, args);
  }

  if (isnull(fixes))
  {
    args = make_list(func_name, 'fixes');
    return return_error(_DOC_MISSING_ARG_TEMPLATE, args);
  }

  if (isnull(severity))
  {
    args = make_list(func_name, 'severity');
    return return_error(_DOC_MISSING_ARG_TEMPLATE, args);
  }

  if (typeof(install) != 'array')
  {
    args = make_list(func_name, 'array');
    return return_error(_DOC_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (typeof(fixes) != 'array')
  {
    args = make_list(func_name, 'fixes', 'list');
    return return_error(_DOC_ARG_BAD_TYPE_TEMPLATE, args);
  }

  # Default value.
  if (isnull(min)) min = DOC_NO_MIN;

  # Generate the alternate version for the install.
  alt_version = _make_alt_version(install['display_version']);
  if (alt_version[0] == DOC_OK) alt_version = alt_version[1];
  else exit(1, "Could not parse install version " + install['display_version'] + ".");

  # Determine which fix is appropriate for install.
  foreach fix (fixes)
  {
    # Validate fix data type.
    if (typeof(fix) != 'array' || empty(fix) || len(fix) > 2)
    {
      args = make_list(func_name, "fix" ,"list with 1 or 2 elements");
      return return_error(_DOC_ARG_BAD_TYPE_TEMPLATE, args);
    }

    fix_version = _make_alt_version(fix[0] - DOC_HOTFIX);
    if (fix_version[0] == DOC_OK) fix_version = fix_version[1];
    else exit(1, "Could not parse fix version " + fix[0] + ".");

    # We're going to call a branch a major version, minor version plus
    # service pack number. i.e. 7.1.0 or 6.7.1
    fix_branch = split(fix_version, sep:'.', keep:FALSE);
    fix_branch = fix_branch[0] + "." + fix_branch[1] + "." + fix_branch[2];

    # By default, a fix applies to any version in its branch unless
    # a minimum is specified. If DOC_NO_MIN is specified, then the
    # fix applies to any version below it regardless of branch.
    if (isnull(fix[1]))
    {
      min = fix_branch;
    }
    else if(fix[1] == DOC_NO_MIN)
    {
      min = DOC_NO_MIN;
    }
    else
    {
      min = _make_alt_version(fix[1] - DOC_HOTFIX);
      if (min[0] == DOC_OK) min = min[1];
      else exit(1, "Could not parse min version " + fix[1] + ".");
    }

    if (ver_compare(ver:alt_version, fix:min, strict:FALSE) >= 0)
    {
      comparison = ver_compare(ver:alt_version, fix:fix_version, strict:FALSE);
      # Compare version to fix and report.
      if (comparison == -1)
      {
        vuln = TRUE;
        break;
      }
      else if (DOC_HOTFIX >< fix[0] && report_paranoia > 1)
      {
        local_var fix_split, ver_split, index;
        # If this is a hotfix release, then we flag anything that
        # matches the hotfix  or before (so a 7.0 hotfix would flag
        # any 7.0.x version). PARANOID only.
        fix_split = split(fix_version, sep:'.', keep:FALSE);
        ver_split = split(alt_version, sep:'.', keep:FALSE);

        # Assume vuln, and set vuln to false if we find a mismatch
        # between the fix and the version.
        vuln = TRUE;
        foreach index (keys(fix_split))
        {
          if (fix_split[index] != ver_split[index])
          {
            vuln = FALSE;
            break;
          }
        }

        # If vuln is still TRUE, then we're done and we can proceed
        # to report.
        if (vuln) break;
      }
    }
  }

  if (vuln)
  {
    # Add KB flag if needed.
    if (xss) set_kb_item(name:'www/0/XSS', value:TRUE);
    if (xsrf) set_kb_item(name:'www/0/XSRF', value:TRUE);
    if (sqli) set_kb_item(name:'www/0/SQLInjection', value:TRUE);

  report =
      '\n  Path              : ' + install['path'] +
      '\n  Installed version : ' + install['display_version'] +
      '\n  Fixed version     : ' + fix[0] +
      '\n';
    security_report_v4(port:0, extra:report, severity:severity);
    exit(0);
  }
  else audit(AUDIT_INST_PATH_NOT_VULN, DOC_APP_NAME, install['display_version'], install['path']);
}
