# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# appletv_func.inc
# $Revision: 1.1 $
#
# @NOGPL@
#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

APPLETV_MODEL_GEN = make_array(
  # model, generation
  '1,1', 1,
  '2,1', 2,
  '3,1', 3,
  '3,2', 3,
  '5,3', 4
);

function missing_param(func, name, value)
{
  if (empty_or_null(value))
  {
    err_print(func + ': invalid ' + name + ' ' + name + '=', value);
    return TRUE;
  }
  else return FALSE;
}

function cmp_appletv_build(build, fix)
{
  if (empty_or_null(build) || empty_or_null(fix)) return NULL;
  # ensure build char is numeric value
  if (typeof(build['char']) != "int") build['char'] = ord(build['char']);
  if (typeof(fix['char'])   != "int") fix['char']   = ord(fix['char']);

  local_var build_str = build['major'] + "." + build['char'] + "." + build['minor'];
  local_var fix_str = fix['major'] + "." + fix['char'] + "." + fix['minor'];
  return ver_compare(ver:build_str, fix:fix_str, strict:FALSE);
}

function appletv_build_to_array(build)
{
  local_var pat = "([0-9]+)([A-Za-z])([0-9]+)([A-Za-z]+)?";
  local_var matches = pregmatch(pattern:pat, string:build, icase:TRUE);
  if (isnull(matches)) return NULL;
  else
  {
    if (len(matches) <= 3) return NULL;
    else
    {
      local_var major = int(matches[1]);
      local_var char  = ord(matches[2]);
      local_var minor = int(matches[3]);
      return make_array('major', major, 'char', char, 'minor', minor);
    }
  }
}

##
# Determine if an Apple TV product is vulnerable
#
# Function returns NULL on error, or nothing at all. If no errors are
# encountered, reporting will occur.
#
# @param build The detected build/version number
# @param fix The fixed build/version number
# @param min The minimum build (Optional param)
# @param model The detected Apple TV model number (Optional param - must be paired with gen)
# @param gen The affected Apple TV generation (Optional param - must be paired with model)
# @param port The port the Apple TV responded on
# @param url The URL the Apple TV responded on
# @param severity The severity rating for reporting
# @param xss A boolean value to determine if the XSS kb item has to be set (Optional param)
# @param xsrf A boolean value to determine if the XSRF kb item has to be set (Optional param)
# @param fix_tvos_ver The tvOS version number (e.g. 9.2.2) that should be displayed in the report (Optional param)
#
# @return NULL if there is an error
#
##
function appletv_check_version(build, fix, min, model, gen, port, url, severity, xss, xsrf, fix_tvos_ver)
{
  local_var func = 'appletv_check_build';
  local_var report = '';

  # ensure required parameters are given and have values
  if (missing_param(func:func, name:'build', value:build) ||
      missing_param(func:func, name:'fix', value:fix) ||
      missing_param(func:func, name:'severity', value:severity) ||
      missing_param(func:func, name:'port', value:port) ||
      missing_param(func:func, name:'url', value:url)
  )
  {
    return NULL;
  }

  # ensure model is proper generation, if supplied
  if (!empty_or_null(model) && !empty_or_null(gen))
  {
    local_var model_pat = "([0-9]+,[0-9]+)";
    local_var model_matches = pregmatch(pattern:model_pat, string:model, icase:TRUE);

    if (isnull(model_matches))
    {
      if (report_paranoia < 2) exit(0, "The model number for this Apple TV is invalid.");
    }
    else
    {
      local_var model_gen = APPLETV_MODEL_GEN[model_matches[1]];
      if (!isnull(model_gen) && !empty_or_null(gen) && model_gen != gen)
      {
        audit(AUDIT_HOST_NOT, "a Generation " + gen + " Apple TV");
      }
    }
  }

  # extract build parts
  local_var build_arr = appletv_build_to_array(build:build);
  if (isnull(build_arr)) audit(AUDIT_VER_FORMAT, build);

  # ensure build is min or higher, if supplied
  if (!empty_or_null(min))
  {
    # validate min
    local_var min_arr = appletv_build_to_array(build:min);
    if (isnull(min_arr)) audit(AUDIT_VER_FORMAT, min);

    if (cmp_appletv_build(build:build_arr, fix:min_arr) < 0)
      audit(AUDIT_HOST_NOT, "affected because it is running build " + build);
  }

  local_var fix_arr = appletv_build_to_array(build:fix);
  if (isnull(fix_arr))   audit(AUDIT_VER_FORMAT, fix);

  # now check if build < fix
  if (cmp_appletv_build(build:build_arr, fix:fix_arr) < 0)
  {
    report =
      '  URL             : ' + url   + '\n' +
      '  Installed build : ' + build + '\n' +
      '  Fixed build     : ' + fix;

    if (!empty_or_null(fix_tvos_ver))
      report += ' (Apple TV ' + fix_tvos_ver + ')';

    report += '\n';

    security_report_v4(
      port     : port,
      extra    : report,
      severity : severity,
      xss      : xss,
      xsrf     : xsrf
    );
  }
  else audit(AUDIT_HOST_NOT, "affected because it is running build " + build);
}
