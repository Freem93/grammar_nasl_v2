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
# ibm_rational_clearquest_version.inc
# $Revision: 1.1 $
#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

##
# Convert file version to a user friendly version
# (e.g. 8.103.1.422 to 8.0.1.3.1)
#
# @param  array ver of file from hotfix_get_fversion()
#                 (e.g. [0: 8][1: 103][2: 1][3: 422])
#                 nb a string can also be passed (e.g. 8.103.1.422)
#
# @return user friendly version (e.g. 8.0.1.3.1)
#         NULL otherwise
##
function rational_clearquest_ver_to_verui(ver)
{
  local_var ver_ui, tmp, ifix;

  if (isnull(ver))
  {
    err_print("rational_clearquest_ver_to_verui : 'ver' is required.");
    return NULL;
  }
                               # Example - 8.103.1.422
  ver_ui   = ver[0] + '.';     # 8.
  tmp      = ver[1];           # 103
  ver_ui  += tmp / 1000 + '.'; # 8.0.
  tmp     %= 1000;             # 103
  ver_ui  += tmp / 100 + '.';  # 8.0.1.
  tmp     %= 100;              # 3
  ver_ui  += tmp;              # 8.0.1.3

  # Interim fix
  ifix = ver[2];              
  if (!isnull(ifix) && ifix > 0) 
    ver_ui += '.' + ifix;      # 8.0.1.3.1 

  return ver_ui;
}

##
# Performs a version check for IBM Rational ClearQuest
#
# @param  list    fixes nested list of arrays containing the 'Min',
#                 'Fix', 'Fix UI' versions
# @param  string  severity rating for reporting
# @param  list    components OPTIONAL required for the host to be affected
#                   Possible values:
#                     Web Client, Client for Windows, Client, Mail Service, Maintenance Tool
# @param  boolean xss OPTIONAL determine if the XSS kb item has to be set
# @param  boolean xsrf OPTIONAL determine if the XSRF kb item has to be set
# @param  boolean sqli OPTIONAL determine if the SQLInjection kb item has to be set
# @param  boolean paranoid OPTIONAL only run if paranoid reporting is enabled
#
# @return NULL if there is an error
#
##
function rational_clearquest_check_version(fixes, severity, components, xss, xsrf, sqli, paranoid)
{
  local_var appname, install;
  local_var version, version_ui, path;
  local_var component_installed, component;
  local_var fix, report;

  # Paranoid report check
  if (isnull(paranoid)) paranoid = FALSE;
  if (paranoid && report_paranoia < 2) audit(AUDIT_PARANOID);

  # Validate parameters
  if (empty_or_null(fixes)) 
  {
    err_print("rational_clearquest_check_version : 'fixes' parameter is empty.");
    return NULL;
  }

  # Retrieve product info
  appname    = 'IBM Rational ClearQuest';
  install    = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);

  version    = install['version'];
  version_ui = install['display_version'];
  path       = install['path'];
 
  # Component check
  component_installed = FALSE;
  if (!empty_or_null(components))
  {
    foreach component (components)
    {
      if (!isnull(install[component]))
      {
        component_installed = TRUE;
        break; # we only need one component to continue
      }
    }
    if (!component_installed)
    {
      if (len(components) == 1)
        audit(AUDIT_HOST_NOT,
          "affected because the affected component '"+components[0]+"' is not installed.");
      else
        audit(AUDIT_HOST_NOT,
          "affected because the affected components '" +
          join(components, sep:"' or '")+" are not installed.");
    }
  }
  # fixes is a nested list of arrays with the keys "Regex", "Fix", "Fix UI"
  foreach fix (fixes)
  {
    # Validate 'Fix' and 'Fix UI'
    if (empty_or_null(fix["Fix"]) || empty_or_null(fix["Fix UI"]))
    {
      err_print("rational_clearquest_check_version : 'Fix' and 'Fix UI' must be specified in 'checks'.");
      return NULL;
    }
    if (fix["Fix"] !~ "^[0-9.]+$")
    {
      err_print("rational_clearquest_check_version : invalid 'Fix' specified in checks :", fix["Fix"]);
      return NULL;
    }

    # Check the version, making sure we are in the correct branch if needed
    #  If 'Min' version is omitted, check against all previous versions
    if (
      isnull(fix["Min"])
        ||
      (fix["Min"] && ver_compare(ver:version_ui, fix:fix["Min"], strict:FALSE) >= 0)
    )
    {
      if (ver_compare(ver:version, fix:fix["Fix"], strict:FALSE) < 0)
      {
        report =
          '\n  Path              : ' + path +
          '\n  Installed version : ' + version_ui    + ' (' + version + ')' + 
          '\n  Fixed version     : ' + fix["Fix UI"] + ' (' + fix["Fix"] + ')' +
          '\n';

        if (xss)
          set_kb_item(name:'www/0/XSS', value:TRUE);
        if (xsrf)
          set_kb_item(name:'www/0/XSRF', value:TRUE);
        if (sqli)
          set_kb_item(name:'www/0/SQLi', value:TRUE);

        security_report_v4(port:0, extra:report, severity:severity);
        exit(0);
      }
    }
  }
  if (isnull(report)) audit(AUDIT_INST_PATH_NOT_VULN, appname, version_ui, path);
}
