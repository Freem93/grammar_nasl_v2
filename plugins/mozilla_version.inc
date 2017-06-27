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
# tomcat_version.inc
# $Revision: 1.2 $
#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

MOZ_PRODUCTS = make_array('firefox', 'Firefox', 'thunderbird', 'Thunderbird', 'seamonkey', 'Seamonkey');

##
# Determine to check if a Mozilla product is vulnerable
#
# @param installs An array of install keys
# @param product The product we are checking for.  Should be 'firefox', 'thunderbird', or 'seamonkey'
# @param esr A boolean value to determine if we are checking the ESR branch
# @param fix The fixed version
# @param min The minimum version, used to specify a branch
# @param skippat The pattern of branches to skip
# @param severity The severity rating for reporting
# @param xss A boolean value to determine if the XSS kb item has to be set
# @param xsrf A boolean value to determine if the XSRF kb item has to be set
#
# @return NULL if there is an error
#
##
function mozilla_check_version(installs, version, path, product, esr, fix, min, skippat, severity, xss, xsrf)
{
  local_var key, match, report, port;
  local_var info, ver_esr, esr_ui, be;

  if (esr) esr_ui = ' ESR';
  else esr_ui = '';

  report = '';
  info = '';

  # Validate parameters
  if (fix !~ '^[0-9\\.]+$') 
  {
    err_print('mozilla_check_version: invalid version fix=', fix);
    return NULL;
  }
  if (min && min !~ '^[0-9\\.]+$')
  {
    err_print('mozilla_check_version: invalid version min=', min);
    return NULL;
  }
  if (isnull(product))
  {
    err_print('mozilla_check_version: invalid product product=', product);
    return NULL;
  }
  product = tolower(product);
  if (product != 'firefox' && product != 'thunderbird' && product != 'seamonkey') 
  {
    err_print('mozilla_check_version: invalid product product=', product);
    return NULL;
  }

  if (isnull(installs))
  {
    key = 'MacOSX/' + MOZ_PRODUCTS[product];
    if (get_kb_item(key + '/is_esr'))
      ver_esr = ' ESR';
    else
      ver_esr = '';
    if (isnull(version) || isnull(path))
    {
      err_print('mozilla_check_version: missing version or path');
      return NULL;
    }
    # Check the version, making sure we are in the correct branch if needed
    if (!min || (min && ver_compare(ver:version, fix:min, strict:FALSE) >= 0))
    {
      if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
      {
        report +=
          '\n  Path              : ' + path +
          '\n  Installed version : ' + version + ver_esr +
          '\n  Fixed version     : ' + fix + esr_ui +
          '\n';
        if (xss)
          set_kb_item(name:'www/0/XSS', value:TRUE);
        if (xsrf)
          set_kb_item(name:'www/0/XSRF', value:TRUE);
        security_report_v4(port:0, extra:report, severity:severity);
        exit(0);
      }
      audit(AUDIT_INST_PATH_NOT_VULN, 'Mozilla ' + MOZ_PRODUCTS[product], version + ver_esr, path);
    }
    else
      audit(AUDIT_INST_PATH_NOT_VULN, 'Mozilla ' + MOZ_PRODUCTS[product], version + ver_esr, path);
  }
  else
  {
    port = get_kb_item('SMB/transport');
    if (!port) port = 445;

    foreach key (keys(installs))
    {
      if (get_kb_item(key + '/is_esr'))
        ver_esr = ' ESR';
      else
        ver_esr = '';

      match = eregmatch(string:key, pattern:'/([a-zA-Z]+)/([0-9.]+)$');
      if (isnull(match)) continue;
      # Check that we are looking at the expected product
      if (tolower(match[1]) !~ product) continue;
  
      # Grab the version and the path
      version = match[2];
      path = installs[key];

      if (esr)
      {
        # Skip the is_esr key, and make sure the product is the ESR branch
        if ('is_esr' >< key) continue;
        if (!ver_esr)
        {
          info += ' and ' + version + ver_esr;
          continue;
        }
      }
      else
      {
        if (ver_esr)
        {
          info += ' and ' + version + ver_esr;
          continue;
        }
      }

      # Check the version, making sure we are in the correct branch if needed
      if (skippat && version =~ skippat) continue;
      if (!min || (min && ver_compare(ver:version, fix:min, strict:FALSE) >= 0))
      {
        if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
        {
          report += 
            '\n  Path              : ' + path +
            '\n  Installed version : ' + version + ver_esr +
            '\n  Fixed version     : ' + fix + esr_ui +
            '\n';
        }
        else
          info += ' and ' + version + ver_esr;
      }
      else
        info += ' and ' + version + ver_esr;
    }
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

      exit(0, 'The host is not affected since Mozilla ' + MOZ_PRODUCTS[product] + ' ' + info + ' ' + be + ' installed.');
    }
  }
  exit(0);
}
