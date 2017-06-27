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
# websphere_portal_version.inc
# $Revision: 1.6 $
#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("install_func.inc");

# Return codes for portlet check
PORTLET_VULN        = 3;
PORTLET_NOT_VULN    = 2;
PORTLET_NOT_INST    = 1;
PORTLET_WP_NOT_VULN = 0;
PORTLET_ERROR       = -1;

global_var app_name, cell, errors;

app_name = "IBM WebSphere Portal";
cell     = NULL;
errors   = NULL;

##
# Check the cumulative fix (CF) level.
#
# @param string cf_ver build or fixlevel to parse CF from
# @param string cf_fix Fixed CF to compare
#
# @return -1    CF version <  CF fix
#          0    CF version == CF fix
#          1    CF version >  CF fix
## 
function websphere_portal_cf_check(cf_ver, cf_fix)
{
  local_var matches;

  matches = eregmatch(pattern:"CF([0-9]+)", string:cf_fix);
  if (isnull(matches[1]))
  {
    err_print('websphere_portal_cf_check: invalid cf_fix=', cf_fix);
    exit(1);
  }
  else
    cf_fix = int(matches[1]);

  matches = eregmatch(pattern:"CF([0-9]+)", string:cf_ver);

  # Default to 00 (no CF) if no match is found in the build
  if (isnull(matches[1])) cf_ver = 00;
  else cf_ver = int(matches[1]); 

  # nb: the max is used as the fixed version with the CF
  if (cf_ver < cf_fix)  return -1;
  if (cf_ver == cf_fix) return 0;
  else return 1;
}

##
# Check if the efix or efixes are installed.
#
# @param string installed_efixes efixes installed on host
# @param string efix   OPTIONAL efix to check for (e.g. PI1234)
# @param string efixes OPTIONAL efixes to check for (e.g. PI1234, PI5678)
#                               all efixes must be installed
#
# @return -1    fixed eFix(es) not installed
#          0    fixed eFix(es) installed
#          NULL an error occurred
##
function websphere_portal_efix_check(installed_efixes, efix, efixes)
{
  local_var i, missing_efixes, has_efixes;

  if (efix)
  {
    if (isnull(installed_efixes))
    {
      errors += '\tAn error occurred attempting to retrieve installed eFixes.\n';
      return NULL;
    }

    # No eFixes are installed -- install is vulnerable
    # nb: eFixes value is set to FALSE if no eFixes are detected
    if (!installed_efixes)
      return -1;

    installed_efixes = split(installed_efixes, sep:', ', keep:FALSE);

    foreach i (installed_efixes)
      if (i == efix)
        return 0;
    return -1;
  }

  # eFixes check
  else if (efixes)
  {
    if (isnull(installed_efixes))
    {
      errors += '\tAn error occurred attempting to retrieve installed eFixes.\n';
      return NULL;
    }

    # No eFixes installed
    if (!installed_efixes)
      return -1;

    efixes = split(efixes, sep:', ', keep:FALSE);

    has_efixes = make_list();
    missing_efixes = make_list();

    # Compare installed eFixes to the fixed eFixes
    foreach efix (efixes)
    {
      if (ereg(string:installed_efixes, pattern:efix + "(,|$)"))
        has_efixes = make_list(has_efixes, efix);
      else
        missing_efixes = make_list(missing_efixes, efix);
    }

    has_efixes = list_uniq(has_efixes);

    # Check if ALL eFixes are applied
    if (max_index(has_efixes) == max_index(efixes))
      return 0;

    # At least one eFix is not installed
    if (!empty(missing_efixes))
      return -1;
  }
}


##
# Check if the eFix, eFixes, or cumulative fix (CF) are installed or
# compare versions
#
# @param array  install contains info such as installed eFixes, build
# @param string ver version to be checked
# @param string fix is either eFix, eFix, CF, or version 
# @param string min OPTIONAL min version
# @return -1    fix is not installed / ver < fix
#          0    fix is installed / ver == fix
#          1    ver > fix
#          NULL an error occurred
##
function websphere_portal_ver_cmp(install, ver, fix, min, max)
{
  local_var ret, ver_fix, path;

  # Parse fix
  # cumulative fix (e.g. CF08)
  if (fix =~ "^CF[0-9]+$")
    ret = websphere_portal_cf_check(cf_ver:install['Build'], cf_fix:fix);

  # eFix (e.g. PI1234)
  else if (fix =~ "^[A-Z]+[0-9]+$")
    ret = websphere_portal_efix_check(installed_efixes:install['eFixes'], efix:fix);

  # eFixes (e.g. PI1234, PI5678)
  else if (fix =~ "^[A-Z]+[0-9]+,")
    ret = websphere_portal_efix_check(installed_efixes:install['eFixes'], efixes:fix);

  # version fix (e.g. 7.0.0.1)
  else if (fix =~ "^[0-9]+\.$")
  {
    if (!min || (min && ver_compare(ver:ver, fix:min, strict:FALSE) >= 0))
    {
      ret = ver_compare(ver:ver, fix:ver_fix, strict:FALSE);
      if (ret < 0)       return -1;
      else if (ret == 0) return 0;
      else               return 1;
    }
    else return 1;
  }
  
  # invalid fix
  else
  {
    err_print('websphere_portal_ver_cmp: invalid fix=', fix);
    exit(1);
  }

  return ret;
}

##
# Determine if WebSphere Portal is vulnerable
#
# @param  string  fix OPTIONAL used when only one fix is specified;
#                 must be used with ranges
# @param  list    ranges OPTIONAL list of min/max versions separated with
#                 a comma (e.g 7.0.0.0, 7.0.0.2)
# @param  array   checks OPTIONAL keys must be min/max versions separated with
#                 a comma (e.g 7.0.0.0, 7.0.0.2) with lists of fixes
#                 as the values. Fixes are one or more efix, efixes,
#                 cumulative fix, version fix.
# @param  array   portlets OPTIONAL portlets to check for
# @param  list    req_vuln_portlets OPTIONAL portlet which must be
#                 vulnerable for other checks to be performed 
# @param  string  severity The severity rating for reporting
# @param  boolean xss OPTIONAL determine if the XSS kb item has to be set
# @param  boolean xsrf OPTIONAL determine if the XSRF kb item has to be set
# @param  boolean sqli OPTIONAL determine if the SQLInjection kb item has to be set
#
# @return NULL  if there is an error
#
##
function websphere_portal_check_version(fix, ranges, checks, portlets, req_vuln_portlets, severity, xss, xsrf, sqli)
{
  local_var install, i, matches;
  local_var portlet_wp_not_vuln, portlet, vuln_portlets;
  local_var range, ver, path;
  local_var missing_fix;
  local_var min, max, cf_req;
  local_var cf_range, cf_low, cf_high, not_affected;
  local_var ret, port;
  local_var report, unaffected;

  unaffected    = make_list();
  vuln_portlets = make_list();

  # Validate parameters
  if (!checks && (!fix && empty_or_null(ranges)) && empty_or_null(portlets)) 
  {
    err_print("websphere_portal_check_version: 'fix' along with 'ranges' or 'checks' arguments OR 'portlets' argument is required");
    exit(1);
  }

  if (severity !~ '(Note|Warning|Hole)')
  {
    err_print("websphere_portal_check_version: invalid severity");
    exit(1);
  }

  install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);

  ver  = install['version'];
  path = install['path'];

  # Remove \ if its the last character
  matches = eregmatch(pattern:"(.*)\\$", string:path);
  if (!isnull(matches[1]))
    path = matches[1]; 

  # Portlets check
  portlet_wp_not_vuln = 0;

  foreach portlet (keys(portlets))
  {
    ret = websphere_portal_check_portlet(
      portlet          : portlet,
      path             : path,
      file             : path + portlets[portlet]["File"],
      cell_file        : portlets[portlet]["Cell File"],
      fix              : portlets[portlet]["Fixed Version"],
      version_regex    : portlets[portlet]["Version Regex"],
      build_fix        : portlets[portlet]["Build Fix"],
      build_regex      : portlets[portlet]["Build Regex"],
      wp_version       : ver,
      wp_ranges        : portlets[portlet]["WP Ranges"]
    );
    
    if (ret[0] == PORTLET_VULN) # affected portlet detected
    {
      report += ret[1];
      vuln_portlets = make_list(vuln_portlets, portlet);
    }
    else if (ret[0] == PORTLET_WP_NOT_VULN) # installed WebSphere Portal version is not affected
    {
      portlet_wp_not_vuln++;
      unaffected = make_list(unaffected, ret[1]);
    }
    else if (ret[0] == PORTLET_NOT_VULN) # unaffected portlet detected
      unaffected = make_list(unaffected, ret[1]); 
    else if (ret[0] == PORTLET_NOT_INST) # portlet is not installed
      unaffected = make_list(unaffected, ret[1]);
    else if (ret[0] == PORTLET_ERROR) # an error occurred
      errors += ret[1];
  }

  if (!empty_or_null(portlets))
    hotfix_check_fversion_end();

  # req_vuln_portlets - Check that installed WebSphere Portal is in range of affected versions
  if (!empty_or_null(req_vuln_portlets) &&
    (portlet_wp_not_vuln == max_index(keys(portlets)))
  )
    audit(AUDIT_INST_PATH_NOT_VULN, app_name, ver, path);
  
  # req_vuln_portlets - Check that required portlet is installed
  if (!empty_or_null(req_vuln_portlets) &&  
    (max_index(req_vuln_portlets) != max_index(vuln_portlets))
  )
    exit(0, "The " + app_name + " version " + ver + " install under " +
      path + " is not affected because the affected portlet(s) are not installed.");

  if (!empty(unaffected))
    unaffected = join(list_uniq(unaffected), sep:'\n');
  else
    unaffected = ''; # so we don't try to append a list to a string below 
 
  missing_fix = make_list();

  if (ranges)
    foreach i (ranges)
      checks[i] = make_list(fix); 


  # nb: Min/max versions are used as the key (e.g. "7.0.0.0, 7.0.0.2",)
  foreach i (keys(checks))
  {
    # Parse and validate min and max versions
    range = split(i, sep:', ', keep:FALSE);
    min   = range[0];
    max   = range[1];
    if (!isnull(range[2]))
      cf_req = range[2];    

    if (min !~ '^[0-9\\.]+$')
    {
      err_print('websphere_portal_check_version: invalid min=', min);
      exit(1);
    }
    if (max !~ '^[0-9\\.]+$')
    {
      err_print('websphere_portal_check_version: invalid max=', max);
      exit(1);
    }
    if (min && max && ver_compare(ver:min, fix:max, strict:FALSE) > 0)
    {
      err_print('websphere_portal_check_version: min must be less than or equal to max');
      exit(1);
    }
    if (!isnull(cf_req) && cf_req !~ '^CF[0-9]+(-CF[0-9]+)?$')
    {
      err_print('websphere_portal_check_version: invalid cf_req=', cf_req);
      exit(1);
    }

    # Check if version is in range of affected versions
    if (
      ver_compare(ver:ver, fix:min, strict:FALSE) >= 0 &&
      ver_compare(ver:ver, fix:max, strict:FALSE) <= 0
    )
    {        
      # Check if installed CF version is lower than the installed CF version
      if (!isnull(cf_req))
      {
        if ('-' >< cf_req)
        {
          cf_range = split(cf_req, sep:'-', keep:FALSE);
          cf_low   = cf_range[0];
          cf_high  = cf_range[1];

          if (
            websphere_portal_cf_check(cf_ver:install['Build'], cf_fix:cf_low)  < 0 ||
            websphere_portal_cf_check(cf_ver:install['Build'], cf_fix:cf_high) > 0
          ) not_affected = TRUE;
        }
        else if (websphere_portal_cf_check(cf_ver:install['Build'], cf_fix:cf_req) == 1)
          not_affected = TRUE;

        if (not_affected)
          exit(0,
            'The ' + app_name + ' version ' + ver + ' Build ' + install['Build'] +
            ' install under ' + path + ' is not affected.\n\n' + unaffected); 
      }
      # Check each fix
      # nb: if fixes are in one string (e.g. "PI15690, PI12345"), then
      #     all fixes must be installed on the host; otherwise, only
      #     one of the fixes is required
      foreach fix (checks[i])
      {
        ret = websphere_portal_ver_cmp(install:install, ver:ver, fix:fix, min:min, max:max);
        if (isnull(ret)) continue;
        if (ret < 0)
          missing_fix = make_list(missing_fix, fix);
        else
          exit(0,
            'The ' + app_name + ' version ' + ver + ' install under ' + path +
            ' is not affected.\n\n' + unaffected);
      }
    }
  
    # Compare number of missing fixes to fixes 
    if (
      (!isnull(fix) || !empty_or_null(checks)) && 
      (max_index(missing_fix) == max_index(checks[i]))
    )
    {
      report =
        '\n  Path              : ' + path +
        '\n  Installed version : ' + ver + ' Build ' + install['Build'] +
        '\n  Missing ';
      if (max_index(missing_fix) == 1)
        report += 'fix       : ';
      else if (max_index(missing_fix) > 1)
        report += 'fixes     : ';
      report += join(list_uniq(missing_fix), sep:' or ') + '\n';
    }

  }

  # Report findings
  if (report)
  {
    port = get_kb_item('SMB/transport');
    if (!port) port = 445;

    if (xss)
      set_kb_item(name:'www/0/XSS', value:TRUE);
    if (xsrf)
      set_kb_item(name:'www/0/XSRF', value:TRUE);
    if (sqli)
      set_kb_item(name:'www/0/SQLInjection', value:TRUE);

    security_report_v4(port:port, extra:report, severity:severity);
    exit(0);
  }
  
  # Report errors
  if (!isnull(errors))
    exit(1, 'The following error(s) occurred :\n' + errors);
  else
    exit(0,
      'The '+ app_name +' version '+ ver +' install under '+path+' is not affected.\n\n' +
      unaffected);
}


##
# Check if Portals are installed and parse version
#
# @param  string  portlet name to be checked
#                 nb: used just for reporting
# @param  string  path of WebSphere Portal
# @param  string  file path that contains portlet info
#                 nb: this should be the path after the WebSphere
#                 Portal (e.g. \paa\portlet_name\)
# @param  string  cell_file path to portlet
#                 nb: cell name must be parsed and included in path                
# @param  string  fix OPTIONAL portlet fixed portlet version
# @param  string  version_regex OPTIONAL regex to parse portlet version
# @param  string  wp_version OPTIONAL version of WebSphere Portal
# @param  list    wp_ranges OPTIONAL min, max versions of WebSphere Portal
#                 (e.g. make_list("7.0.0.0, 7.0.0.2", "8.0.0.0, 8.0.0.1")
# @param  string  build_fix OPTIONAL fixed portlet version
# @param  string  build_regex OPTIONAL regex to parse portlet build
#
# @return  list   return value,     message string 
#                 PORTLET_VULN,     affected version detected
#                 PORTLET_NOT_VULN, unaffected version detected
#                 PORTLET_NOT_INST, portlet not installed
#                 PORTLET_ERROR,    error report
#          int    PORTLET_WP_NOT_VULN, detected WebSphere Portal is not in range 
##
function websphere_portal_check_portlet(portlet, path, file, cell_file, fix, version_regex, wp_version, wp_ranges, build_fix, build_regex)
{
  local_var range, min, max, inrange;
  local_var config_file, data, error, matches;
  local_var ver, ver_fix, ver_build;
  local_var build_display, build_fix_display;

  # Validate parameters
  if (empty_or_null(portlet))
  {
    err_print('websphere_portal_check_portlet: invalid portlet=', portlet);
    exit(1);
  }

  if (empty_or_null(file))
  {
    err_print('websphere_portal_check_portlet: invalid file path=', file);
    exit(1);
  }

  if (wp_version && wp_ranges)
  {  
    inrange = FALSE;

    foreach range (wp_ranges)
    {
      # Parse and validate min and max versions
      range = split(range, sep:', ', keep:FALSE);
      min   = range[0];
      max   = range[1];

      if (min && max && ver_compare(ver:min, fix:max, strict:FALSE) > 0)
      {
        err_print('websphere_portal_check_portlet: min must be less than or equal to max');
        exit(1);
      }

      # Make sure the WebSphere Portal version is in range
      if (
        ver_compare(ver:wp_version, fix:min, strict:FALSE) >= 0 &&
        ver_compare(ver:wp_version, fix:max, strict:FALSE) <= 0
      )
      {
        inrange = TRUE;
        break;
      }
    }
    
    if (!inrange)
      return make_list(PORTLET_WP_NOT_VULN,
        portlet + ' Portlet is not affected because ' + app_name + ' ' + wp_version +
        ' is not affected.');
  }

  if (!isnull(cell_file))
  {
    if (wp_version =~ "^[78]\.")
    {
      config_file = NULL;

      # Retrieve active cell
      if (wp_version =~ "^[78]\.")
        config_file = path + "\..\wp_profile\ConfigEngine\properties\wkplc.properties";

      data = hotfix_get_file_contents(config_file);
      error = hotfix_handle_error(
        error_code:data["error"], file:config_file, exit_on_fail:FALSE);
      if (error)
        return make_list(PORTLET_ERROR, '\t' + error + '\n');

      matches = eregmatch(pattern:"CellName=(.*)", string:data["data"]);

      if (!isnull(matches[1]))
        file = path + "\..\wp_profile\installedApps\" + chomp(matches[1]) + cell_file;
    }
    else if (wp_version =~ "^6\.")
      file = path + "\installedApps\" + cell_file;
    else
      return make_list(PORTLET_ERROR, '\t'+app_name+ ' version ' + wp_version + ' is not supported for the cell file check.\n');

  }

  # Portlet check
  if (isnull(hotfix_file_exists(path:file)))
    return make_list(PORTLET_ERROR, '\tAn error occurred while attempting to access ' + file +'.\n');
  else if (!hotfix_file_exists(path:file))
    return make_list(PORTLET_NOT_INST,
      portlet + ' Portlet for ' + app_name +
      ' does not appear to be installed because ' + file + ' is missing.');

  # Appears to only be a file check
  if (isnull(fix))
    return make_list(PORTLET_VULN, 'The file ' + file + ' exists on the host.\n');

  data = hotfix_get_file_contents(file);
  error = hotfix_handle_error(error_code:data["error"], file:file, exit_on_fail:FALSE);
  if (error)
    return make_list(PORTLET_ERROR, '\t' + error + '\n');
  # Parse version
  matches = pregmatch(pattern:version_regex, string:data["data"]);
  if (isnull(matches[1]))
    return make_list(PORTLET_ERROR,
      '\tFailed to parse version of '+portlet+' from '+file+'.\n');

  ver               = matches[1];
  ver_fix           = fix;
  build_display     = NULL;
  build_fix_display = NULL;
  

  # Build info included
  if (!empty_or_null(build_fix) && !empty_or_null(build_regex))
  {
    matches = eregmatch(pattern:build_regex, string:data["data"]);
    if (!isnull(matches[1]))
    {
      ver_build = ver + "." + matches[1];
      ver_fix   = ver_fix +     "." + build_fix;
      build_display     = " Build " + matches[1];
      build_fix_display = " Build " + build_fix;
    }
    else
      return make_list(PORTLET_ERROR, '\tFailed to parse build of '+portlet+' from '+file+'.\n');
  }
  
  # Affected version detected
  if (ver_compare(ver:ver, fix:ver_fix, strict:FALSE) == -1)
  {
    return make_list(PORTLET_VULN,
      '\n  Detected version of ' + portlet  + ' Portlet : ' + ver + build_display +
      '\n  Fixed version of ' + portlet + ' Portlet    : ' + fix + build_fix_display +
      '\n');
  }
  else
  {
    return make_list(PORTLET_NOT_VULN,
      'The ' + portlet + ' Portlet for ' + app_name + ' version ' + ver +
      build_display + ' installed under ' + file + ' is not affected.'
    );
  }
}
