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
# google_chrome_version.inc
# $Revision: 1.2 $
#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

##
# Determine to check if Google Chrome is vulnerable
#
# @param installs An array of install keys, not to be included on Mac OS X checks
# @param fix The fixed version
# @param min The minimum version, used to specify a branch
# @param severity The severity rating for reporting
# @param xss A boolean value to determine if the XSS kb item has to be set
# @param xsrf A boolean value to determine if the XSRF kb item has to be set
#
# @return NULL if there is an error
#
##
function google_chrome_check_version(installs, version, path, fix, min, severity, xss, xsrf)
{
  local_var install, report, port;
  local_var info, be;
  local_var macosx_check, kb_base;

  report = '';
  info = '';

  # Validate parameters
  if (fix !~ '^[0-9\\.]+$') 
  {
    err_print('google_chrome_check_version: invalid version fix=', fix);
    return NULL;
  }
  if (min && min !~ '^[0-9\\.]+$')
  {
    err_print('google_chrome_check_version: invalid version min=', min);
    return NULL;
  }


  if (isnull(installs))
  {
    macosx_check = TRUE;
    port = 0;
    installs = get_kb_list("MacOSX/Google Chrome/*");
  }
  else
  {
    macosx_check = FALSE;
    port = get_kb_item('SMB/transport');
    if (!port) port = 445;
  }

  foreach install (sort(keys(installs)))
  {
    if ("/Installed" >< install) continue;

    if (!macosx_check)
      kb_base = "SMB/Google_Chrome/";
    else
      kb_base = "MacOSX/Google Chrome/";

    version = install - kb_base;
    if (!macosx_check)
      version = version - (strstr(version, "/"));
    else
      version = substr(version, stridx(version, "/") + 1);
    path = installs[install];


    if (!min || (min && ver_compare(ver:version, fix:min, strict:FALSE) >= 0))
    {
      if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
      {
        report += 
          '\n  Path              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : ' + fix +
          '\n';
      }
      else
        info += ' and ' + version;
    }
    else
      info += ' and ' + version;
  }

  if (report)
  {
    if (xss)
      set_kb_item(name:'www/' + port + '/XSS', value:TRUE);
    if (xsrf)
      set_kb_item(name:'www/' + port + '/XSRF', value:TRUE);
    security_report_v4(port:port, extra:report, severity:severity);
    exit(0);
  }
  else
  {
    if (info)
    {
      info -= ' and ';
      if (' and ' >< info) be = 'are';
      else be = 'is';

      exit(0, 'The host is not affected since Google Chrome ' + info + ' ' + be + ' installed.');
    }
  }
  exit(0);
}
