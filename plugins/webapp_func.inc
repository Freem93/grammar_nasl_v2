###
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
# webapp_func.inc
# $Revision: 1.17 $
#
# @include misc_func.inc
# @include http.inc
###

# Plugins should only include either webapp_func.inc or
# install_func.inc, not both.
include("install_func.inc");

##
# Default header used by get_vuln_report()
##
global_var DEFAULT_HEADER;
DEFAULT_HEADER = 'Nessus was able to verify the issue using the following URL';


##
# adds install information to an array of existing install information, and
# saves the info to the KB
#
# @param appname name of installed application. this name is only used internally for KB reading/writing
# @param installs existing list of installs formatted the same as the return value of this function (optional)
# @param dir web dir of install to add
# @param ver version of the install found in 'dir'. this is optional - if no argument is given, the install is given a version of UNKNOWN_VER
# @param port number of the web server where the app was detected
# @param cpe passes CPE attribute to register_install
#
# @remark saves www/"appname"=TRUE in the KB, where "appname" is the argument passed to the "appname" parameter
#
# @return an array - 'installs', with the new install added. key = ver, dir = corresponding dirs, delimited by DIR_SEPARATOR
##
function add_install(appname, installs, dir, ver, port, cpe)
{
  if (isnull(appname))
  {
    err_print("add_install() missing required argument 'appname'.");
    return NULL;
  }
  else if (isnull(dir))
  {
    err_print("add_install() missing required argument 'dir'.");
    return NULL;
  }
  else if (isnull(port))
  {
    err_print("add_install() missing required argument 'port'.");
    return NULL;
  }

  if (isnull(installs)) installs = make_array();
  if (isnull(ver)) ver = UNKNOWN_VER;

  if (dir == '') dir = '/';

  set_kb_item(
    name:'www/' + port + '/' + appname,
    value:ver + ' under ' + dir
  );

  # General key to allow optimization with script_require_keys
  set_kb_item(name: 'www/'+appname, value: TRUE);

  register_install(
    app_name:appname,
    path:dir,
    version:ver,
    port:port,
    cpe:cpe,
    webapp:TRUE
  );

  # base64 encodes dirs to prevent any delimiter ambiguity
  dir = base64(str:dir);
  if (isnull(installs[ver])) installs[ver] = dir;
  else installs[ver] += SEPARATOR + dir;

  return installs;
}


##
# Generates plugin output containing information on all installs detected
#
# @param display_name name of the web application being reported on. this is the name that will be displayed in the report
# @param installs installs to report. this should be an array with the same that [add_install] returns
# @param port number of the web server where the app was detected
# @param item page in each install directory where the app was detected. '/' by default.
#
# @return a report of installs detected if any were detected, NULL otherwise
##
function get_install_report(display_name, installs, port, item)
{
  local_var info, version, n, dir, dirs, url, report;

  if (isnull(display_name))
  {
    err_print("get_install_report() missing required argument 'display_name'.");
    return NULL;
  }
  else if (isnull(port))
  {
    err_print("get_install_report() missing required argument 'port'.");
    return NULL;
  }

  # Bail out if there's nothing to report (i.e. nothing was detected)
  if (isnull(installs) || max_index(keys(installs)) == 0) return NULL;

  if (isnull(item)) item = '/';

  info = "";
  n = 0;

  foreach version (sort(keys(installs)))
  {
    info += '\n  Version : ' + version + '\n';
    dirs = split(installs[version], sep:SEPARATOR, keep:FALSE);

    foreach dir (sort(dirs))
    {
      dir = base64_decode(str:dir);
      if (dir == '/') url = item;
      else url = dir + item;

      info += '  URL     : ' + build_url(port:port, qs:url) + '\n';
      n++;
    }
  }

  report = '\nThe following instance';
  if (n == 1) report += ' of ' + display_name + ' was';
  else report += 's of ' + display_name + ' were';
  report += ' detected on the remote host :\n' + info;

  return report;
}

##
# Generates plugin output containing information used to detect/verify a vulnerability is present
#
# @param header header of plugin output. if this arg is omitted, DEFAULT_HEADER is used
# @param trailer plugin output trailer (optional)
# @param items list of web paths (including query strings, if applicable) that demonstrate the vulnerability. this can either be a string (if there is only one item), or a list of strings
# @param port number of the web server where the app was detected
#
# returns plugin output demonstrating the vulnerability, or NULL if there were any errors generating the plugin output
##
function get_vuln_report(header, trailer, items, port)
{
  local_var report, item;

  if (isnull(items))
  {
    err_print("get_vuln_report() missing required argument 'items'.");
    return NULL;
  }
  else if (isnull(port))
  {
    err_print("get_vuln_report() missing required argument 'port'.");
    return NULL;
  }

  items = make_list(items);
  if (max_index(items) == 0) return NULL;

  if (isnull(header))
  {
    header = DEFAULT_HEADER;
    if (max_index(items) > 1) header += 's';
  }

  report = string("\n", header, " :\n");

  foreach item (items)
    report += string("\n  ", build_url(qs:item, port:port), "\n");

  if (!isnull(trailer))
    report += string("\n", trailer, "\n");

  return report;
}

##
# Gets a web app install from the KB
#
# @param appname name of the app, as it was stored in the KB (by [add_install])
# @param port number of the web server where the app was detected
# @param exit_on_fail if TRUE, exits in lieu of returning NULL. FALSE by default
#
# @remark This function will fork if multiple installations of the same web app are read from the KB.
#         If you need a non-forking alternative, consider [get_dirs_from_kb]
#
# @return an array if the application was found in the KB ("ver" => detected version, "dir" => web dir where the app is installed),
#         NULL otherwise
##
function get_install_from_kb(appname, port, exit_on_fail)
{
  local_var install, match, dir, ver, ret;
  local_var installs;

  if (isnull(appname))
  {
    err_print("get_install_from_kb() missing required argument 'appname'.");
    return NULL;
  }
  else if (isnull(port))
  {
    err_print("get_install_from_kb() missing required argument 'port'.");
    return NULL;
  }
  if (isnull(exit_on_fail)) exit_on_fail = FALSE;

  ret = NULL;
  installs = get_installs(app_name:appname, port:port);
  if (installs[0] == IF_NOT_FOUND)
  {
    if (exit_on_fail)
      exit(0, "No installs of " + appname + " on port " + port + " were found.");
    else
      return NULL;
  }
  else if (installs[0] != IF_OK)
  {
    if (exit_on_fail)
      exit(0, "Could not retrieve installs of " + appname + " on port " + port + ".");
    else
      return NULL;
  }

  installs = installs[1];

  # This function is expected to fork if there are multiple installs
  # so we have to do that explicitly now to maintain backwards
  # compatibility.
  install = branch(installs);

  # Strip the trailing slash from the dir, if it has one
  dir = ereg_replace(string:install['path'], pattern:'^(/.*)/$', replace:"\1");
  if (dir == '/') dir = '';

  ret = make_array(
    'dir', dir,
    'ver', install['version']);

  return ret;
}

##
# Gets a list from the KB of all the web dirs where the given app was detected.
#
# @param appname name of the app, as it was stored in the KB (by [add_install])
# @param port number of the web server where the app was detected
# @param exit_on_fail if TRUE, exits in lieu of returning NULL. FALSE by default
#
# @return a list of web dirs if the application was found in the KB, NULL otherwise
##
function get_dirs_from_kb(appname, port, exit_on_fail)
{
  local_var install, installs, match, dir, ret;

  if (isnull(appname))
  {
    err_print("get_dirs_from_kb() missing required argument 'appname'.");
    return NULL;
  }
  else if (isnull(port))
  {
    err_print("get_dirs_from_kb() missing required argument 'port'.");
    return NULL;
  }
  if (isnull(exit_on_fail)) exit_on_fail = FALSE;

  ret = make_list();

  installs = get_installs(app_name:appname, port:port);
  if (installs[0] == IF_OK)
  {
    installs = installs[1];
  }

  else if (installs[0] == IF_NOT_FOUND)
  {
    if (exit_on_fail)
      exit(0, "No installs of " + appname + " on port " + port + " were found.");
    else
      return NULL;
  }
  else if (installs[0] != IF_OK)
  {
    if (exit_on_fail)
      exit(0, "Could not retrieve installs of " + appname + " on port " + port + ".");
    else
      return NULL;
  }

  foreach install (installs)
  {
    # Strip the trailing slash from the dir, if it has one
    dir = ereg_replace(string:install['path'], pattern:'^(/.*)/$', replace:"\1");
    if (dir == '/') dir = '';
    ret = make_list(ret, dir);
  }

  return ret;
}

##
# Finds installations of a web application.
#
# @param all             Whether all contrel regexes need to match, default TRUE
# @param appname         The name of the web application
# @param checks          An array with nested lists of regexes
#
# @param add_headers     Passed to [http_network#http_send_recv3]
# @param content_type    Passed to [http_network#http_send_recv3]
# @param cpe             Passed to [add_install], optional
# @param data            Passed to [http_network#http_send_recv3]
# @param exit_on_fail    Passed to [http_network#http_send_recv3], default TRUE
# @param fetch404        Passed to [http_network#http_send_recv3]
# @param follow_redirect Passed to [http_network#http_send_recv3]
# @param host            Passed to [http_network#http_send_recv3]
# @param method          Passed to [http_network#http_send_recv3], default "GET"
# @param no_body         Passed to [http_network#http_send_recv3]
# @param only_content    Passed to [http_network#http_send_recv3]
# @param password        Passed to [http_network#http_send_recv3]
# @param port            Passed to [http_network#http_send_recv3], required
# @param target          Passed to [http_network#http_send_recv3]
# @param transport       Passed to [http_network#http_send_recv3]
# @param username        Passed to [http_network#http_send_recv3]
# @param version         Passed to [http_network#http_send_recv3]
#
# @return The value from running [add_install] on each instance.
##
function find_install(
  add_headers, all, appname, checks, content_type, cpe, data, dirs,
  exit_on_fail, fetch404, follow_redirect, host, method, no_body,
  only_content, password, port, target, transport, username
)
{
  local_var dir, installed, installs, matched, matches, regex;
  local_var regexes, res, url, version;

  # Sanity check parameters.
  if (isnull(appname) || isnull(checks) || isnull(dirs) || isnull(port))
    return NULL;

  # Set defaults.
  if (isnull(all))
    all = TRUE;
  if (isnull(exit_on_fail))
    exit_on_fail = TRUE;
  if (isnull(method))
    method = "GET";
  if (isnull(cpe))
    cpe = '';

  installs = NULL;

  foreach dir (dirs)
  {
    installed = FALSE;
    version = NULL;

    foreach url (keys(checks))
    {
      # Request the page from the web server.
      res = http_send_recv3(
        item            : dir + url,

        add_headers     : add_headers,
        content_type    : content_type,
        data            : data,
        exit_on_fail    : exit_on_fail,
        fetch404        : fetch404,
        follow_redirect : follow_redirect,
        host            : host,
        method          : method,
        no_body         : no_body,
        only_content    : only_content,
        password        : password,
        port            : port,
        target          : target,
        transport       : transport,
        username        : username,
        version         : version
      );

      # Get the regexes that we'll be using to process this page.
      regexes = checks[url];

      # Ensure that the control regexes match, so we're confident that
      # we have the page we expected.
      matched = 0;
      foreach regex (regexes[0])
      {
        if (!egrep(string:res[2], pattern:regex))
          continue;

        matched++;
        if (!all)
          break;
      }

      # If the page didn't live up to our expectations, move on to the
      # next URL.
      if (matched == 0 || (all && matched != max_index(regexes[0])))
        continue;

      # Remember that we did find the page we expected, so the
      # application is definitely installed.
      installed = TRUE;

      # Extract the version number from the page. Try every regex
      # until one works.
      foreach regex (regexes[1])
      {
        matches = eregmatch(string:res[2], pattern:regex, icase:TRUE);
        if (!isnull(matches))
        {
          version = matches[1];
          break;
        }
      }

      # If we've got a version number, we've no reason to continue.
      if (!isnull(version))
        break;
    }

    # If we haven't discovered an installation on any of the URLs,
    # then we'll move on to the next directory.
    if (!installed)
      continue;

    # Register the installed instance.
    installs = add_install(
      installs : installs,
      port     : port,
      dir      : dir,
      appname  : appname,
      ver      : version,
      cpe      : cpe
    );

    # Only continue looking for additional installations if we're being
    # thorough.
    if (!thorough_tests)
      break;
  }

  return installs;
}

##
# Gets PHP version and source from the KB
# @param port number of the web server where PHP was detected
# @param exit_on_fail if TRUE, exits.  FALSE by default
#
# @return an array if PHP was found in the KB
# ("ver" => detected version, "src" => source used to identify the source)
# Otherwise NULL
##
function get_php_from_kb(port, exit_on_fail)
{
  local_var php, match, src, ver, ret;

  if (isnull(port))
  {
    err_print("get_php_from_kb() missing required argument 'port'.");
    return NULL;
  }
  if (isnull(exit_on_fail)) exit_on_fail = FALSE;

  ret = NULL;

  php = get_kb_item('www/php/' + port + '/version');
  if (isnull(php))
  {
    if (exit_on_fail)
      exit(0, "The 'www/php/"+port+"/version' KB item is missing.");
    else
      return NULL;
  }
  match = eregmatch(string:php, pattern:'(.+) under (.+)$');
  if (!isnull(match))
  {
    ver = match[1];
    src = match[2];
    src = ereg_replace(string:src, pattern:", $", replace:"");

    ret = make_array(
      'ver', ver,
      'src', src
    );
  }
  return ret;
}

# Checks for existance of a plugin / extension for webapp.  Useful for
# WordPress plugins, Joomla extesions, etc.
#
# @param all             Whether all regexes need to match, default TRUE
# @param checks          An arrary with lists of regexes
# @param dirs            A list of dirs to test
# @param ext             The name of the webapp extension
#
# @param add_headers     Passed to [http_network#http_send_recv3]
# @param content_type    Passed to [http_network#http_send_recv3]
# @param data            Passed to [http_network#http_send_recv3]
# @param exit_on_fail    Passed to [http_network#http_send_recv3], default TRUE
# @param fetch404        Passed to [http_network#http_send_recv3]
# @param follow_redirect Passed to [http_network#http_send_recv3]
# @param host            Passed to [http_network#http_send_recv3]
# @param method          Passed to [http_network#http_send_recv3], default "GET"
# @param no_body         Passed to [http_network#http_send_recv3]
# @param only_content    Passed to [http_network#http_send_recv3]
# @param password        Passed to [http_network#http_send_recv3]
# @param port            Passed to [http_network#http_send_recv3], required
# @param target          Passed to [http_network#http_send_recv3]
# @param transport       Passed to [http_network#http_send_recv3]
# @param username        Passed to [http_network#http_send_recv3]
# @param version         Passed to [http_network#http_send_recv3]
#
# @return Boolean : TRUE if extension is found / FALSE if not
##
function check_webapp_ext(
 all, checks, dir, ext, add_headers, content_type, data, exit_on_fail,
 fetch404, follow_redirect, host, method, no_body, only_content, password,
 port, target, transport, username, version
)
{
 local_var res, matched, found, url, regexes, regex;

 if (isnull(checks)  || isnull(dir))
   return NULL;

 # Defaults
 if (isnull(all))
   all = TRUE;
 if (isnull(exit_on_fail))
   exit_on_fail = TRUE;
 if (isnull(method))
   method = "GET";

 foreach url (keys(checks))
 {
   found = FALSE;
   res = http_send_recv3(
     item            : dir + url,
     add_headers     : add_headers,
     content_type    : content_type,
     data            : data,
     exit_on_fail    : exit_on_fail,
     fetch404        : fetch404,
     follow_redirect : follow_redirect,
     host            : host,
     method          : method,
     no_body         : no_body,
     only_content    : only_content,
     password        : password,
     port            : port,
     target          : target,
     transport       : transport,
     username        : username,
     version         : version
   );

   # Get the regexes that we'll be using to process this page.
   regexes = checks[url];

   # Ensure that the control regexes match, so we're confident that
   # we have the page we expected.
   matched = 0;
   foreach regex (regexes[0])
   {
     if (!egrep(string:res[2], pattern:regex))
       continue;

     matched++;
     if (!all)
       break;
   }
   # If the page didn't live up to our expectations, move on to the
   # next URL.
   if (matched == 0 || (all && matched != max_index(regexes[0])))
     continue;

   # Web app ext found
   found = TRUE;
   replace_kb_item(name:'www/'+port+'/webapp_ext/'+ext+' under '+dir, value:TRUE);
   break;
 }
 return found;
}
