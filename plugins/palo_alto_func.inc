##
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# palo_alto_func.inc
#
# $Revision: 1.1 $
##

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# External use globals
global_var PALO_ALTO_VERSION, PALO_ALTO_APP_NAME, PALO_ALTO_FIX_VER;

# Internal use globals
global_var __PALO_ALTO_VERSION_KB;

##
# Location of the Palo Alto device version
#
# @remark modified by function calls
##
__PALO_ALTO_VERSION_KB = "Host/Palo_Alto/Firewall/Version"; 

##
# Default label for Palo Alto devices
#
# @remark used in report generation
##
PALO_ALTO_APP_NAME = "Palo Alto Networks PAN-OS";

##
# Applicable fix version based on device version
#
# @remark modified by function calls
# @remark used in report generation
##
PALO_ALTO_FIX_VER = NULL;  

##
# Version of Palo Alto device is stored here
#
# @remark modified by function calls
# @remark used in report generation
##
PALO_ALTO_VERSION = NULL;

##
# Flag for checking whether or not to audit or return
#
# @remark Set to 1 here, will audit with 1, otherwise will return.
# @remark The TAP test will set PALO_ALTO_USE_AUDITS to 0.
##
PALO_ALTO_USE_AUDITS = 1;

##
# Checks Palo Alto version using KB entry. If not written,
# audit out.
# 
# @remark Writes PALO_ALTO_VERSION
#
# @return version string if KB entry exists
#         audit out/return NULL otherwise based on PALO_ALTO_USE_AUDITS
##
function palo_alto_store_version()
{
  PALO_ALTO_VERSION = get_kb_item(__PALO_ALTO_VERSION_KB);
  if (isnull(PALO_ALTO_VERSION))
  {
    if (PALO_ALTO_USE_AUDITS == 1) audit(AUDIT_KB_MISSING,__PALO_ALTO_VERSION_KB);
    else return NULL;
  }
  # For testing
  return PALO_ALTO_VERSION;
}

##
# Determines if any of the key regexes apply to Palo Alto version,
# and returns appropriate fix value when one does.
# 
# @param fix_array Array containing regex keys and fix version values
# @param version Version string of device
#
# @remark Writes PALO_ALTO_FIX_VER
#
# @return fix_ver if any of the regex keys match the version
#         audit out/return NULL otherwise based on PALO_ALTO_USE_AUDITS
##
function palo_alto_determine_fix_ver(version,fix_array)
{
  local_var ver_regex, fix_ver;
  foreach ver_regex (keys(fix_array))
  {
    fix_ver = fix_array[ver_regex];
    if (ereg(pattern:ver_regex, string:version))
    {
      PALO_ALTO_FIX_VER = fix_ver;
      return fix_ver;
    }
  }
  if (PALO_ALTO_USE_AUDITS == 1) audit(AUDIT_OS_RELEASE_NOT,PALO_ALTO_APP_NAME,PALO_ALTO_VERSION);
  else return NULL;
}

##
# Determines if the PALO_ALTO_VERSION value has granularity
#   problems when compared with PALO_ALTO_FIX_VER
# 
# @return 0 if version has at least as much granularity as
#           the fix version
#         audit out/return -1 otherwise based on PALO_ALTO_USE_AUDITS
##
function palo_alto_check_granularity()
{
  local_var fix_split,ver_split,fix_levels,ver_levels;
  fix_split = split(PALO_ALTO_FIX_VER, sep:".", keep:FALSE);
  ver_split = split(PALO_ALTO_VERSION, sep:".", keep:FALSE);
  fix_levels = max_index(fix_split);
  ver_levels = max_index(ver_split);
  if (ver_levels < fix_levels)
  {
    if (PALO_ALTO_USE_AUDITS == 1) audit(AUDIT_VER_NOT_GRANULAR, PALO_ALTO_APP_NAME, PALO_ALTO_VERSION);
    else return -1;
  }
  return 0;
}

##
# Compares version to fix version, and reports if necessary.
# 
# @param fix Version string of fixed version
# @param version Version string of device
# @param xss Flag TRUE to mark KB as XSS
# @param xsrf Flag TRUE to mark KB as XSRF
# @param sqli Flag TRUE to mark KB as SQLInjection
# @param severity Severity level of report as defined in global_settings.inc
#
# @remark supply xss/xsrf/sqli TRUE to write any of those KBs
#
# @return security report based on severity if affected
#         audit out/return -1 otherwise based on PALO_ALTO_USE_AUDITS
##
function palo_alto_check_version(version,fix,xss,xsrf,sqli,severity)
{
  local_var port, report;
  port = 0;
  # Compare version to fix and report as needed.
  if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
  {
    if (!isnull(xss) && xss == TRUE) set_kb_item(name:'www/0/XSS', value:TRUE);
    if (!isnull(xsrf) && xsrf == TRUE) set_kb_item(name:'www/0/XSRF', value:TRUE);
    if (!isnull(sqli) && sqli == TRUE) set_kb_item(name:'www/0/SQLInjection', value:TRUE);
    if (report_verbosity > 0)
    {
      report =
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
      if (severity == SECURITY_HOLE)
        security_hole(port:port, extra:report);
      else if (severity == SECURITY_WARNING)
        security_warning(port:port, extra:report);
      else
        security_note(port:port, extra:report);
    }
    else
    {
      if (severity == SECURITY_HOLE)
        security_hole(port:port);
      else if (severity == SECURITY_WARNING)
        security_warning(port:port);
      else
        security_note(port:port);
    }
    if (PALO_ALTO_USE_AUDITS == 1) exit(0);
    else return report;
  }
  else
  {
    if (PALO_ALTO_USE_AUDITS == 1) audit(AUDIT_OS_RELEASE_NOT,PALO_ALTO_APP_NAME,PALO_ALTO_VERSION);
    else return -1;
  }
}

##
# Executes functions to determine Palo Alto version, find appropriate
#   fix version, check if the versions are granular enough, and then
#   perform version checking and reporting.
# 
# @param fix_array Array containing regex keys and fix version values
# @param xss Flag TRUE to mark KB as XSS
# @param xsrf Flag TRUE to mark KB as XSRF
# @param sqli Flag TRUE to mark KB as SQLInjection
# @param severity Severity level of report as defined in global_settings.inc
#
# @remark supply xss/xsrf/sqli TRUE to write any of those KBs
#
# @return security report based on severity if affected
#         return NULL otherwise
##
function palo_alto_check(fix_array,xss,xsrf,sqli,severity)
{
  if (!isnull(palo_alto_store_version()) &&
      !isnull(palo_alto_determine_fix_ver(version:PALO_ALTO_VERSION,fix_array:fix_array)) &&
      palo_alto_check_granularity() >= 0
  )
  {
    return palo_alto_check_version(version:PALO_ALTO_VERSION,fix:PALO_ALTO_FIX_VER,xss:xss,xsrf:xsrf,sqli:sqli,severity:severity);
  }
  return NULL;
}
