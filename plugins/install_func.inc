#TRUSTED 93ae253c6495c879aa56a0d3ba9aeca1e5b9b72e13257444f489dcdd9a3509888c8b7177f9b5a733715af088b0bf46e37c615d1e3d214187578539a27ea65311e73c45dcc0feb7741875a8b95fa8eeb8fd9a5e5a535eddba8286865adb251a68e6143e36a32567dfc1d80a469a73233e195a64d9913a0f6d97f516caab69b014d735b958aab73c503cc18f48b2c4cf14884db65c710078311b042800e3d2a498f04b4b67ee5fc4b6a185bdd0f923c3ac9637114fba6e7d93be9f237ffdd98c89ad105df64ee3749f8286215fd116f12d88ef34ad6c33ad9da1f4146334726284e5c0e3071140b6586ddcd17163e5f156392f7d4daed36b712ad3f027f49f1e964b62c6cf22f7d7ff57f5865fa0aa8458bdd566d8db8b8d2cffa73b4f905a355bd869f56d7f473287bc903b50cce0efedbe5bfb1415535d5082904218c81a1f453aac921042924cef80175efc14dbc397603287d72809642e5b02051dd6f7a9d65966f69aacff4f16efb7468f7ac70f89116747cca34a8d0cd8c072bf0e0f8be71faf3a32c28959a8333494c8d1fb5b2addaa92d256183724b98d7498c65636436ce7b9860ddc3d4abc207ffd5f4f72b3154c41d3a05a85f8dbd133f4b6f3c1b12f1ec3d43acff84fedc980f1bc5f7615c5cdccfb1a2e6f60314c46d834750d51ed31f501cb261e05628758f727ac60c0044355002ad66e0835472d896cac5939
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
# install_func.inc
#
# Revision: 1.14
#
# @include audit.inc
# @include global_settings.inc
# @include misc_func.inc
# @include string.inc
###
#

include("string.inc");

### Constants ###
DISPLAY_VERSION_KEY = '/display_version';
LIST_BULLET         = '- ';
PATH_REPORT_KEY     = 'Path';
PRIORITY_KEY        = '/priority';
ROOT_KB_KEY         = 'installed_sw/';
SEPARATOR           = ';';     # Default separator for lists in KB.
SOURCE_KEY          = 'Source';
UNKNOWN_VER         = "unknown";
VERSION_KEY         = '/version';
VERSION_REPORT_KEY  = 'Version';

### Debug Flag ###
IF_VERBOSE_ERRORS = FALSE;

### get_single_install Flag ###
IF_GSI_CALLED = make_array();

# Return Codes
# Negative values are conditions that should not occur at run-time
# Positive values can occur at run-time and should be handled
# gracefully.
IF_LOWER_PRIORITY  = 2;   # Install is lower priority than existing.
IF_NOT_FOUND       = 1;   # No installs found.
IF_OK              = 0;   # Successful return.
IF_ERROR           = -1;  # General/Unknown/Upstream error.
IF_MISSING_ARG     = -2;  # Missing argument to function.
IF_ARG_BAD_TYPE    = -3;  # Function argument is the wrong type.
IF_UNEXPECTED_NULL = -4;  # Unexpected NULL value encountered.
IF_PARSE_ERROR     = -5;  # Failed to parse input.
IF_MISSING_FUNC    = -6;  # Missing function definition. Indicates missing include.

# Source Priorities
IF_PRIORITY_HIGH   = 1;
IF_PRIORITY_NORMAL = 0;
IF_PRIORITY_LOW    = -1;
IF_PRIORITY_LOWER  = -2;

# Error Templates
IF_ERROR_TEMPLATE = make_list(1, "%s(): Unknown or upstream error occurred.", IF_ERROR);
IF_MISSING_ARG_TEMPLATE = make_list(2, "%s(): missing required argument '%s'.", IF_MISSING_ARG);
IF_ARG_BAD_TYPE_TEMPLATE = make_list(3, "%s(): '%s' arg must be type '%s'.", IF_ARG_BAD_TYPE);
IF_UNEXPECTED_NULL_TEMPLATE = make_list(2, "%s(): '%s' variable is unexpectedly NULL.", IF_UNEXPECTED_NULL);
IF_PARSE_ERROR_TEMPLATE = make_list(2, "%s(): Failure parsing variable '%s'.", IF_PARSE_ERROR);
IF_MISSING_FUNC_TEMPLATE = make_list(3, "%s(): The function '%s' is not defined. Try including '%s'.", IF_MISSING_FUNC);

### Globals ###
InstallReport = make_array();   # Report for all installs found.
InstallCount = make_array();    # Number of installs found.

### Functions ###

# Get both and local and remote (combined) installs
#
# @param  string app_name
# @param  int     exit_if_not_found OPTIONAL defaults to FALSE, exits
#                 if no installs of app_name are found.
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a list of installs s.t. that each
#                          install is an array containing all the data
#                          stored in the KB.
#                          (NULL if ret[0] != IF_OK)
##
function get_combined_installs(app_name, exit_if_not_found)
{
  local_var installs, local_installs, remote_installs,
            install, tmp, port, args, func_name, i;

  if (isnull(app_name))
  {
    args = make_list(func_name, 'app_name');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  # Default value
  if (isnull(exit_if_not_found)) exit_if_not_found = FALSE;

  # report on both local and remote installs
  installs = make_list();

  local_installs = get_installs(app_name: app_name);
  
  if(local_installs[0] == IF_OK) installs = make_list(installs, local_installs[1]);
  remote_installs = get_kb_list(ROOT_KB_KEY+ "*/" + app_name + "/*" + VERSION_KEY);
  
  if(!isnull(remote_installs))
  {
    foreach install(keys(remote_installs))
    {
       tmp = split(install, sep:'/',  keep:FALSE);
       port = int(tmp[1]);
       remote_installs = get_installs(app_name: app_name, port:port);
       if(remote_installs[0] == IF_OK)
       {
         # add port information to array
         for (i=0; i<max_index(remote_installs[1]); i++)
           remote_installs[1][i]["port"] = port;
         installs = make_list(installs, remote_installs[1]);
       }
    }
  }
  
  if(max_index(installs) == 0)
  {
    if(exit_if_not_found) audit(AUDIT_NOT_INST, app_name);
    return make_list(IF_NOT_FOUND);
  }
  else
  {
    return make_list(IF_OK, make_nested_list(installs));
  }
}

##
# Registers an application install in the KB.
#
# @param  string  app_name
# @param  string  path will be base-64 encoded in KB key.
# @param  string  version OPTIONAL defaults to UNKNOWN_VER
# @param  string  version OPTIONAL used in report if supplied
# @param  int     port OPTIONAL if supplied, install KB key is
#                 'installed_sw/<port>/<app_name>/<path>/
# @param  string  cpe OPTIONAL i.e. cpe:/a:adobe:acrobat_reader
# @param  array   extra OPTIONAL Array keys must be strings, values
#                 may be strings, ints or lists. Lists will be stored
#                 in KB as SEPARATOR separated strings.
# @param  array   extra_no_report OPTIONAL like extra but not included
#                 in report
# @param  bool    webapp OPTIONAL if TRUE reports path as URL
# @param  int     priority OPTIONAL defaults to IF_PRIORITY_NORMAL
# @param  string  rep_path OPTIONAL if set appends string to webapp
#                 path created by build_url2()
#
# @remark This function has a side effect of creating KB items to
#         store the install data passed to it. Additionally, it will
#         update a 'installed_sw/<app_name>' key that counts the
#         number of installs of <app_name>.
#
# @return IF_OK if successful
#         IF_ERROR otherwise
##
function register_install(app_name, path, version, display_version, port, cpe, extra,
  extra_no_report, webapp, priority, rep_path)
{
  local_var func_name, args;
  local_var install_kb_key, app_kb_key;
  local_var install_added;
  local_var report_version, report_path, p_extra;

  func_name = 'register_install';

  # Input validation.
  if (isnull(app_name))
  {
    args = make_list(func_name, 'app_name');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (isnull(path))
  {
    args = make_list(func_name, 'path');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  # If app is a webapp, we need a port.
  if (webapp && isnull(port))
  {
    args = make_list(func_name, 'port');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (!isnull(port) && typeof(port) != 'int')
  {
    args = make_list(func_name, 'port', 'int');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(extra) && typeof(extra) != 'array')
  {
    args = make_list(func_name, 'extra', 'array');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(extra_no_report) && typeof(extra_no_report) != 'array')
  {
    args = make_list(func_name, 'extra_no_report', 'array');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  # Default values.
  if (isnull(version)) version = UNKNOWN_VER;
  if (isnull(webapp)) webapp = FALSE;
  if (isnull(priority)) priority = IF_PRIORITY_NORMAL;

  # Increment install count and save in KB.
  if (isnull(InstallCount[app_name])) InstallCount[app_name] = 1;
  else InstallCount[app_name] += 1;
  replace_kb_item(name:ROOT_KB_KEY + app_name, value:InstallCount[app_name]);

  app_kb_key = make_app_kb_key(app_name:app_name, port:port);
  if (app_kb_key[0] != IF_OK) return IF_ERROR;
  app_kb_key = app_kb_key[1];

  # Set webapp key and ensure we store a path for root installs
  if (webapp)
  {
    if (path == '') path = '/';
    set_kb_item(name:"www/"+port+"/webapp_installed", value:TRUE);
  }

  # Generate install KB key.
  install_kb_key = make_install_kb_key(app_kb_key:app_kb_key, path:path);
  if (install_kb_key[0] != IF_OK) return IF_ERROR;
  install_kb_key = install_kb_key[1];

  # Add data to KB.
  install_added =
    add_install_to_kb(
      install_kb_key:install_kb_key,
      version:version,
      display_version:display_version,
      extra:extra,
      extra_no_report:extra_no_report,
      priority:priority);

  if (install_added == IF_LOWER_PRIORITY) return IF_LOWER_PRIORITY;
  else if (install_added != IF_OK) return return_error(IF_ERROR_TEMPLATE, make_list(func_name));

  # Add install to report.
  if (!isnull(display_version)) report_version = display_version;
  else report_version = version;

  if (webapp)
  {
    if (isnull(rep_path)) p_extra = "";
    else p_extra = rep_path;
    report_path = build_url2(port:port, qs:path + p_extra);

    PATH_REPORT_KEY = 'URL';
  }
  else report_path = path;

  if (
    add_install_to_report(
      app_name:app_name,
      path:report_path,
      version:report_version,
      extra:extra) != IF_OK
    ) return return_error(IF_ERROR_TEMPLATE, make_list(func_name));

  return IF_OK;
}

##
# Creates a base KB key for an application.
#
# @param app_name string
# @param port     int OPTIONAL
#
# @remark This key does NOT end in a '/'.
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a string containing the app KB key
#                          (NULL if ret[0] != IF_OK)
function make_app_kb_key(app_name, port)
{
  local_var func_name, args;
  local_var app_kb_key;

  func_name = "make_app_kb_key";

  # Input validation.
  if (isnull(app_name))
  {
    args = make_list(func_name, 'app_name');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (!isnull(port) && typeof(port) != 'int')
  {
    args = make_list(func_name, 'port', 'int');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  # App KB key consists of ROOT + port, if supplied + app_name
  app_kb_key = ROOT_KB_KEY;
  if (!isnull(port)) app_kb_key += strcat(port, '/');
  app_kb_key += app_name;
  return make_list(IF_OK, app_kb_key);
}

##
# Creates a base KB key for an install.
#
# @param  string  app_name
# @param  string  path
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a string containing the install KB key
#                          (NULL if ret[0] != IF_OK)
##
function make_install_kb_key(app_kb_key, path)
{
  local_var func_name, args;
  local_var install_kb_key, b64_path;

  func_name = 'make_install_kb_key';

  # Input validation.
  if (isnull(app_kb_key))
  {
    args = make_list(func_name, 'app_kb_key');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (isnull(path))
  {
    args = make_list(func_name, 'path');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  # Base KB key starts with app KB key.
  install_kb_key = strcat(app_kb_key, '/');

  # Encode path in base-64 and add to install_kb_key.
  b64_path = IF_base64(path);
  if (b64_path[0] != IF_OK) return make_list(return_error(IF_ERROR_TEMPLATE, make_list(func_name)));
  install_kb_key += b64_path[1];

  return make_list(IF_OK, install_kb_key);
}

##
# Adds install values to the KB.
#
# @param string  install_kb_key
# @param string  version
# @param string  display_version OPTIONAL
# @param array   extra OPTIONAL
# @param array   extra_no_report OPTIONAL
# @param int     priority
#
# @return IF_OK if successful
#         IF_MISSING_ARG if argument is missing
#         IF_ARG_BAD_TYPE if any argument is wrong type
#         IF_ERROR if unknown or upstream error occurs
##
function add_install_to_kb(install_kb_key, version, display_version, extra, extra_no_report,
  priority)
{
  local_var func_name, args;
  local_var existing_priority;

  func_name = 'add_install_to_kb';

  # Input validation.
  if (isnull(install_kb_key))
  {
    args = make_list(func_name, 'install_kb_key');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (isnull(version))
  {
    args = make_list(func_name, 'version');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (isnull(priority))
  {
    args = make_list(func_name, 'priority');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (!isnull(display_version) && !is_string(display_version))
  {
    args = make_list(func_name, 'display_version', 'string');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(extra) && typeof(extra) != 'array')
  {
    args = make_list(func_name, 'extra', 'array');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(extra_no_report) && typeof(extra_no_report) != 'array')
  {
    args = make_list(func_name, 'extra_no_report', 'array');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  # If this install is already registered in the KB, only replace the
  # data if this is a higher priority install.
  existing_priority = get_kb_item(strcat(install_kb_key, PRIORITY_KEY));
  if (!isnull(existing_priority) && existing_priority > priority)
    return IF_LOWER_PRIORITY;

  # If there is an existing install, we need to over-write the source.
  # If we're not already providing one in 'extra' or 'extra_no_report'
  # set it to UNKNOWN_VER.
  if (!isnull(existing_priority) && isnull(extra[SOURCE_KEY]) && isnull(extra_no_report[SOURCE_KEY]))
    extra[SOURCE_KEY] = UNKNOWN_VER;

  # Add priority to KB.
  replace_kb_item(name:strcat(install_kb_key, PRIORITY_KEY), value:priority);

  # Add version to KB.
  replace_kb_item(name:strcat(install_kb_key, VERSION_KEY), value:version);

  # If supplied, add the display version to the KB.
  if (!isnull(display_version))
    replace_kb_item(name:strcat(install_kb_key, DISPLAY_VERSION_KEY), value:display_version);

  if (!empty_or_null(extra))
  {
    if (add_extra_to_kb(install_kb_key:install_kb_key, extra:extra) != IF_OK)
      return return_error(IF_ERROR_TEMPLATE, make_list(func_name));
  }
  if (!empty_or_null(extra_no_report))
  {
    if (add_extra_to_kb(install_kb_key:install_kb_key, extra:extra_no_report) != IF_OK)
      return return_error(IF_ERROR_TEMPLATE, make_list(func_name));
  }

  return IF_OK;
}

##
# Adds extra items to the KB.
#
# @param array extra
# @remark This function has the side effect of modifying the KB.
# @remark List values are joined SEPARATOR separated strings.
#
# @return IF_OK if successful
##
function add_extra_to_kb(install_kb_key, extra)
{
  local_var func_name, args;
  local_var key, value;

  func_name = "add_extra_to_kb";

  # Input validation
  if (isnull(install_kb_key))
  {
    args = make_list(func_name, 'install_kb_key');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (isnull(extra))
  {
    args = make_list(func_name, 'extra');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (typeof(extra) != 'array')
  {
    args = make_list(func_name, 'extra', 'array');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  foreach key (keys(extra))
  {
    value = extra[key];

    if (isnull(value))
    {
      args = make_list(func_name, "extra['" + key + "']");
      return return_error(IF_UNEXPECTED_NULL_TEMPLATE, args);
    }

    if (!is_string(value) && typeof(value) != 'array' && typeof(value) != 'int')
    {
      args = make_list(func_name, "extra['" + key + "']", 'string/list/int');
      return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
    }

    if (typeof(value) == 'array') value = join(value, sep:SEPARATOR);

    replace_kb_item(name:strcat(install_kb_key, '/', key), value:value);
  }

  return IF_OK;
}

##
# Adds the application install to the global report.
#
# @param string   app_name
# @param string   path
# @param string   version
# @param array    extra OPTIONAL
#
# @return IF_OK if successful
#         IF_MISSING_ARG if argument is missing
#         IF_ARG_BAD_TYPE if any argument is wrong type
#         IF_ERROR if unknown or upstream error occurs
##
function add_install_to_report(app_name, path, version, extra)
{
  local_var func_name, args;
  local_var report;
  local_var extra_string, extra_list;
  local_var fields, field_length;

  func_name = 'add_install_to_report';

  # Input validation.
  if (isnull(app_name))
  {
    args = make_list(func_name, 'app_name');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (isnull(path))
  {
    args = make_list(func_name, 'path');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (isnull(version))
  {
    args = make_list(func_name, 'version');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (!isnull(extra) && typeof(extra) != 'array')
  {
    args = make_list(func_name, 'extra', 'array');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  # Initialize report if needed.
  report = InstallReport[app_name];
  if (isnull(report)) report = '';

  # Process extra array.
  if (!isnull(extra))
  {
    extra = process_extra(extra);
    if (extra[0] != IF_OK) return return_error(IF_ERROR_TEMPLATE, make_list(func_name));
    extra_string = extra[1];
    extra_list = extra[2];
  }
  else
  {
    extra_string = NULL;
    extra_list = NULL;
  }

  # Determine field length.
  fields = make_list(PATH_REPORT_KEY, VERSION_REPORT_KEY);
  if (!isnull(extra_string) && len(extra_string) > 0) fields = make_list(fields, keys(extra_string));
  field_length = maxlen(fields);
  if (field_length == -1) return return_error(IF_ERROR_TEMPLATE, make_list(func_name));

  # Add string data to report.
  report =
    add_string_data_to_report(
      report:report,
      path:path,
      version:version,
      extra:extra_string,
      field_length:field_length
    );
  if (report[0] != IF_OK) return return_error(IF_ERROR_TEMPLATE, make_list(func_name));
  report = report[1];

  # Add list data to report.
  if (!isnull(extra_list))
  {
    report =
      add_list_data_to_report(
        report:report,
        extra:extra_list
      );
    if (report[0] != IF_OK) return return_error(IF_ERROR_TEMPLATE, make_list(func_name));
    report = report[1];
  }

  # Store report in global variable.
  InstallReport[app_name] = report;

  return IF_OK;
}

##
# Splits the extra array into two arrays, one containing string values
# the other containing list values.
#
# @param  array extra
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is an array with all the string values
#                   ret[2] is an array with all the list values
##
function process_extra(extra)
{
  local_var func_name, args;
  local_var extra_string, extra_list;
  local_var key, value;
  local_var ret;

  func_name = 'process_extra';

  # Accept argument anonymously.
  if (isnull(extra)) extra = _FCT_ANON_ARGS[0];

  # Input validation.
  if (isnull(extra))
  {
    args = make_list(func_name, 'extra');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (typeof(extra) != 'array')
  {
    args = make_list(func_name, 'extra', 'array');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  # Initialize return values.
  extra_string = make_array();
  extra_list = make_array();

  # Iterate through the array and split into two.
  foreach key (keys(extra))
  {
    value = extra[key];

    if (isnull(value))
    {
      args = make_list(func_name, "extra['" + key + "']");
      return make_list(return_error(IF_UNEXPECTED_NULL_TEMPLATE, args));
    }
    else if (is_string(value))
    {
      extra_string[key] = value;
    }
    else if (typeof(value) == 'array')
    {
      extra_list[key] = value;
    }
    else if (typeof(value) == 'int')
    {
      extra_string[key] = string(value);
    }
    else
    {
      args = make_list(func_name, "extra['" + key + "']", 'string/list');
      return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
    }
  }

  # Build return, can't use make_list because it will flatten
  # extra_string and extra_list. When 5.0 is out of support, replace
  # with make_list2().
  ret[0] = IF_OK;
  ret[1] = extra_string;
  ret[2] = extra_list;

  return ret;
}

##
# Adds top block of string data to install report.
#
# @param string   report
# @param string   path
# @param string   version
# @param array    extra OPTIONAL
# @param int      field_length
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a string containing the modified report
#                          (NULL if ret[0] != IF_OK)
##
function add_string_data_to_report(report, path, version, extra, field_length)
{
  local_var func_name, args;
  local_var format_string;

  func_name = 'add_string_data_to_report';

  # Input validation.
  if (isnull(report))
  {
    args = make_list(func_name, 'report');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (isnull(path))
  {
    args = make_list(func_name, 'path');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (isnull(version))
  {
    args = make_list(func_name, 'version');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (isnull(field_length))
  {
    args = make_list(func_name, 'field_length');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (!isnull(extra) && typeof(extra) != 'array')
  {
    args = make_list(func_name, 'extra', 'array');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  if (typeof(field_length) != 'int')
  {
    args = make_list(func_name, 'field_length', 'int');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  format_string = '\n  %-' + field_length + "s : %s";

  # Add path and version to report.
  report += vsprintf(args:make_list(PATH_REPORT_KEY, path), format:format_string);
  report += vsprintf(args:make_list(VERSION_REPORT_KEY, version), format:format_string);

  # Add string data from extras to report.
  if (!isnull(extra))
  {
    local_var key, value;

    foreach key (sort(keys(extra)))
    {
      value = extra[key];
      if (!is_string(value))
      {
        args = make_list(func_name, "extra['" + key + "']", "string");
        return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
      }

      report += vsprintf(args:make_list(key, value), format:format_string);
    }
  }

  report += '\n';

  return make_list(IF_OK, report);
}

##
# Adds bottom block of list data to install report.
#
# @param string   report
# @param array    extra
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a string containing the modified report
#                          (NULL if ret[0] != IF_OK)
##
function add_list_data_to_report(report, extra)
{
  local_var func_name, args;

  func_name = 'add_list_data_to_report';

  # Input validation.
  if (isnull(report))
  {
    args = make_list(func_name, 'report');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (isnull(extra))
  {
    args = make_list(func_name, 'extra');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (typeof(extra) != 'array')
  {
    args = make_list(func_name, 'extra', 'array');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  # Add list data from extras to report.
  local_var key, value;

  foreach key (sort(keys(extra)))
  {
    local_var element;

    value = extra[key];
    if (typeof(value) != 'array')
    {
      args = make_list(func_name, "extra['" + key + "']", "list");
      return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
    }

    report += '\n  ' + key + ' :';
    foreach element (sort(value)) report += '\n    ' + LIST_BULLET + element;
    report += '\n';
  }

  return make_list(IF_OK, report);
}

##
# Reports detected installs.
#
# @param  string  app_name OPTIONAL if NULL all installs in
#                 InstallReport will be reported.
# @param  int     port OPTIONAL defaults to 0
# @param  string  extra OPTIONAL extra data to be appended to report
# @param  string  protocol OPTIONAL protocol for report
#
# @return IF_OK if successful
#         IF_NOT_FOUND if no install report for that app
#         IF_ERROR otherwise
##
function report_installs(app_name, port, extra, protocol)
{
  local_var func_name, args;
  local_var report;

  func_name = 'report_installs';

  # Input Validation
  if (!isnull(port) && typeof(port) != 'int')
  {
    args = make_list(func_name, 'port', 'int');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  if (!isnull(extra) && !is_string(extra))
  {
    args = make_list(func_name, 'extra', 'string');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  # Default Value
  if (isnull(port)) port = 0;

  # If app_name was not provided, report every installed app.
  # Otherwise, report only on the specified app_name.
  if (isnull(app_name))
  {
    local_var app_count, temp;

    report = '';
    app_count = len(InstallReport);

    foreach app_name (keys(InstallReport))
    {
      # If there is more than one app, add a header with the app name.
      if (app_count > 1) report += '\n--- ' + app_name + ' ---\n';

      # Add the header to the report and check the value.
      temp = add_header_to_report(app_name);
      if (temp[0] != IF_OK) return IF_ERROR;
      report += temp[1];
    }
  }
  else
  {
    report = add_header_to_report(app_name);
    if (report[0] == IF_NOT_FOUND) return IF_NOT_FOUND;
    else if (report[0] != IF_OK) return IF_ERROR;
    report = report[1];
  }

  # Add extra data if it exists.
  if (!isnull(extra)) report += '\n' + extra + '\n';

  # Finally, report.
  if (report_verbosity > 0) security_note(extra:report, port:port, proto:protocol);
  else security_note(port:port, proto:protocol);

  return IF_OK;
}

##
# Adds header to report if install count is greater than 1.
#
# @param string app_name
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a string containing the modified report
#                          (NULL if ret[0] != IF_OK)
##
function add_header_to_report(app_name)
{
  local_var func_name, args;
  local_var report, count;

  func_name = 'add_header_to_report';

  # Allow argument to be passed anonymously.
  if (isnull(app_name)) app_name = _FCT_ANON_ARGS[0];

  # Input validation
  if (isnull(app_name))
  {
    args = make_list(func_name, 'app_name');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  # Retrieve report and exit if either is NULL.
  report = InstallReport[app_name];
  count = InstallCount[app_name];

  if (isnull(report) || isnull(count)) return make_list(IF_NOT_FOUND);

  # Add header to report if install count is greater than 1.
  if (count > 1) report =
    '\nNessus detected ' + count + ' installs of ' + app_name + ':\n' + report;

  return make_list(IF_OK, report);
}

##
# Retrieves all installs of an application/cpe.
#
# @param  string  app_name
# @param  int     port OPTIONAL limits search to remote installs found
#                 on port
# @param  int     exit_if_not_found OPTIONAL defaults to FALSE, exits
#                 if no installs of app_name are found.
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a list of installs s.t. that each
#                          install is an array containing all the data
#                          stored in the KB.
#                          (NULL if ret[0] != IF_OK)
##
function get_installs(app_name, port, exit_if_not_found)
{
  local_var func_name, args;
  local_var app_kb_key, install_kb_keys;
  local_var installs;
  local_var i, ret;

  func_name = 'get_installs';

  # Input Validation
  if (isnull(app_name))
  {
    args = make_list(func_name, 'app_name');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (!isnull(port) && typeof(port) != 'int')
  {
    args = make_list(func_name, 'port', 'int');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  # Default value
  if (isnull(exit_if_not_found)) exit_if_not_found = FALSE;

  app_kb_key = make_app_kb_key(app_name:app_name, port:port);
  if (app_kb_key[0] != IF_OK) return make_list(return_error(IF_ERROR_TEMPLATE, make_list(func_name)));
  app_kb_key = app_kb_key[1];
  # Get a list of KB keys for each install.
  install_kb_keys = find_installs_by_key(app_kb_key);
  if (install_kb_keys[0] == IF_NOT_FOUND)
  {
    if (exit_if_not_found)
    {
      if (isnull(port)) audit(AUDIT_NOT_INST, app_name);
      else audit(AUDIT_NOT_DETECT, app_name, port);
    }
    else return make_list(IF_NOT_FOUND);
  }
  else if (install_kb_keys[0] != IF_OK)
    return make_list(return_error(IF_ERROR_TEMPLATE, make_list(func_name)));

  install_kb_keys = install_kb_keys[1];

  # Populate install data.
  installs = get_install_data_from_keys(install_kb_keys);
  if (installs[0] != IF_OK) return make_list(return_error(IF_ERROR_TEMPLATE, make_list(func_name)));
  installs = installs[1];

  ret = make_list();
  ret[0] = IF_OK;
  ret[1] = installs;

  return ret;
}

##
# Returns a single install of app, branches if there are multiple.
#
# @param  string app_name
# @param  int port OPTIONAL
# @param  bool exit_if_unknown_ver OPTIONAL if TRUE, will exit if
#         version == UNKNOWN_VER. Defaults to FALSE.
# @param  bool combined OPTIONAL if TRUE, will get all local and remote installs
# @remark This function calls get_installs() w/ exit_if_not_found set
#         to TRUE and will exit if there are no installs.
# @remark This function assumes that if looking for an app on several
#         ports, you are branching over the ports as well. That is to
#         say, it does not account for iterating over ports but then
#         branching over installs and will break. Consider it enforced
#         consistency.
#
# @return array single install
##
function get_single_install(app_name, port, exit_if_unknown_ver, combined)
{
  local_var func_name, args;
  local_var installs, install;

  func_name = 'get_single_install';

  # Input Validation
  if (isnull(app_name))
  {
    args = make_list(func_name, 'app_name');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (!isnull(port) && typeof(port) != 'int')
  {
    args = make_list(func_name, 'port', 'int');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  if (isnull(combined)) combined = FALSE;

  if (isnull(exit_if_unknown_ver)) exit_if_unknown_ver = FALSE;

  # This function should only be called once per plugin or you'll end
  # up potentially forking a LOT.
  if (IF_GSI_CALLED[app_name])
    exit(1, "get_single_install() should only be called once per app to avoid excessive forking.");

  IF_GSI_CALLED[app_name] = TRUE;

  if(combined)
    installs = get_combined_installs(app_name:app_name, exit_if_not_found:TRUE);
  else
    installs = get_installs(app_name:app_name, port:port, exit_if_not_found:TRUE);

  if (installs[0] != IF_OK) return return_error(IF_ERROR_TEMPLATE, make_list(func_name));

  install = branch(installs[1]);
  if (isnull(port)) port = install['port'];

  if (exit_if_unknown_ver && install['version'] == UNKNOWN_VER)
  {
    if (!isnull(port)) audit(AUDIT_UNKNOWN_WEB_APP_VER, app_name,build_url2(qs:install['path'], port:port));
    else audit(AUDIT_UNKNOWN_APP_VER, app_name);
  }

  return install;
}

##
# Finds all installs under the app KB key.
#
# @param app_kb_key string
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a list of install KB keys for installs
#                          of app_name (NULL if ret[0] != IF_OK)
##
function find_installs_by_key(app_kb_key)
{
  local_var func_name, args;
  local_var install_kb_version_keys, install_kb_keys;
  local_var key, ret;

  func_name = 'find_installs_by_key';

  # Allow anonymous argument
  if (isnull(app_kb_key)) app_kb_key = _FCT_ANON_ARGS[0];

  # Input validation
  if (isnull(app_kb_key))
  {
    args = make_list(func_name, 'app_kb_key');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  # Search by version since every install is guaranteed to have this
  # key. Then just strip out VERSION_KEY to get the install KB key.
  install_kb_version_keys = get_kb_list(app_kb_key + '/*' + VERSION_KEY);
  if (empty_or_null(install_kb_version_keys))
    return make_list(IF_NOT_FOUND);

  install_kb_keys = make_list();
  foreach key (sort(keys(install_kb_version_keys)))
  {
    install_kb_keys = make_list(install_kb_keys, key - VERSION_KEY);
  }

  ret = make_list();
  ret[0] = IF_OK;
  ret[1] = install_kb_keys;

  return ret;
}

##
# Retrieves data associated with install keys passed in.
#
# @param  list install_kb_keys
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a list of installs s.t. each install is
#                          an array containing install data.
#                          (NULL if ret[0] != IF_OK)
##
function get_install_data_from_keys(install_kb_keys)
{
  local_var func_name, args;
  local_var installs, install, install_kb_key, install_kb_list;
  local_var i, kbs, key, top_key;
  local_var temp, ret;

  func_name = 'get_install_data_from_keys';

  # Allow anonymous argument
  if (isnull(install_kb_keys)) install_kb_keys = _FCT_ANON_ARGS[0];

  # Input validation
  if (isnull(install_kb_keys))
  {
    args = make_list(func_name, 'install_kb_keys');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (typeof(install_kb_keys) != 'array')
  {
    args = make_list(func_name, 'install_kb_keys', 'list');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  installs = make_list();
  i = 0;

  # Get all KBs associated with each install_kb_key and then store the
  # values in an array per install, indexed by the top-level key name.
  foreach install_kb_key (install_kb_keys)
  {
    # Get all KBs for the install.
    install_kb_list = install_kb_key + '/*';
    kbs = get_kb_list(install_kb_list);
    install = make_array();

    # Decode path from install_key and store it in array.
    temp = get_path_from_kb_key(install_kb_key);
    if (temp[0] != IF_OK) return make_list(return_error(IF_ERROR_TEMPLATE, make_list(func_name)));
    install['path'] = temp[1];
    foreach key (keys(kbs))
    {
      # We just want the top-level key as the array index.
      top_key = key - (install_kb_key + '/');

      install[top_key] = kbs[key];
    }

    installs[i] = install;
    i++;
  }

  ret = make_list();
  ret[0] = IF_OK;
  ret[1] = installs;

  return ret;
}

##
# Returns the path associated with an install KB key.
#
# @param  string install_kb_key [description]
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is the base64-decoded path associated
#                          w/ the KB key
#                          (NULL if ret[0] != IF_OK)
##
function get_path_from_kb_key(install_kb_key)
{
  local_var func_name, args;
  local_var pattern, match, path, port_match;

  func_name = 'get_path_from_kb_key';

  # Accept argument anonymously.
  if (isnull(install_kb_key)) install_kb_key = _FCT_ANON_ARGS[0];

  # Input validation.
  if (isnull(install_kb_key))
  {
    args = make_list(func_name, 'install_kb_key');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  pattern = ROOT_KB_KEY + "(?:\d+/)?.+/(.*)";
  match = eregmatch(string:install_kb_key, pattern:pattern, icase:FALSE);
  if (isnull(match))
  {
    args = make_list(func_name, 'install_kb_key');
    return make_list(return_error(IF_PARSE_ERROR_TEMPLATE, args));
  }

  path = IF_base64_decode(match[1]);
  if (path[0] != IF_OK) return make_list(return_error(IF_ERROR_TEMPLATE, make_list(func_name)));

  # Check for webapp by looking for a port in 'install_kb_key'
  # If we have one and the www/port/webapp_installed key is set
  # Check for root installs and return and empty value for the path
  # Otherwise return the path as is
  port_match = eregmatch(pattern:'installed_sw/([0-9]+)/', string:install_kb_key);
  if (!empty_or_null(port_match[1]))
  {
    port_match = port_match[1];
    if (get_kb_item('www/' + port_match + '/webapp_installed'))
    {
      if (path[1] == '/') path[1] = '';
    }
  }
  return make_list(IF_OK, path[1]);
}

##
# Returns the number of installs of 'app_name'.
#
# @param  string  app_name
# @param  bool    exit_if_zero OPTIONAL, if TRUE will exit w/ audit if
#                              install count is 0.
#
# @return int   < 0 if error occurs
#               = 0 if no installs found
#               > 0 if 1 or more installs found
##
function get_install_count(app_name, exit_if_zero)
{
  local_var func_name, args;
  local_var count;

  func_name = 'get_install_count';

  # Input Validation
  if (isnull(app_name))
  {
    args = make_list(func_name, 'app_name');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  # Default Value
  if (isnull(exit_if_zero)) exit_if_zero = FALSE;

  count = get_kb_item(ROOT_KB_KEY + app_name);
  if (isnull(count) || count == 0)
  {
    if (exit_if_zero) audit(AUDIT_NOT_INST, app_name);
    else return 0;
  }

  return count;
}

##
# Encodes a string to base-64 in a 'KB-safe' way.
#
# @param string str string to encode
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is the encoded string
#                          (NULL if ret[0] != IF_OK)
##
function IF_base64(str)
{
  local_var func_name, args;
  local_var b64;

  func_name = 'IF_base64';

  if (isnull(str)) str = _FCT_ANON_ARGS[0];
  if (isnull(str))
  {
    args = make_list(func_name, 'str');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  b64 = base64(str:str);

  b64 = str_replace(string:b64, find:'=', replace:'$');
  b64 = str_replace(string:b64, find:'/', replace:'&');

  return make_list(IF_OK, b64);
}

##
# Decodes a 'KB-safe' base64 string back to ASCII.
#
# @param string str string to decode
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is the decoded string
#                          (NULL if ret[0] != IF_OK)
##
function IF_base64_decode(str)
{
  local_var func_name, args;

  func_name = 'IF_base64';

  if (isnull(str)) str = _FCT_ANON_ARGS[0];
  if (isnull(str))
  {
    args = make_list(func_name, 'str');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  str = str_replace(string:str, find:'$', replace:'=');
  str = str_replace(string:str, find:'&', replace:'/');

  return make_list(IF_OK, base64_decode(str:str));
}

##
# Returns error code for given template and prints error.
#
# @param  list  error_template defined in header
# @param  list  args
#
# @return int   error corresponding to error_template or IF_ERROR if
#               error occurs within this function
##
function return_error(error_template, args)
{
  # Allow arguments to be passed anonymously.
  if (isnull(error_template)) error_template = _FCT_ANON_ARGS[0];
  if (isnull(args)) args = _FCT_ANON_ARGS[1];

  # Input validation.
  if (isnull(error_template))
  {
    err_print("return_error(): missing required argument 'error_template'.");
    return IF_ERROR;
  }

  if (isnull(args))
  {
    err_print("return_error(): missing required argument 'args'.");
    return IF_ERROR;
  }

  if (typeof(error_template) != 'array' || len(error_template) != 3)
  {
    err_print("return_error(): An invalid error template was passed.");
    return IF_ERROR;
  }

  if (typeof(args) != 'array' || len(args) != error_template[0])
  {
    err_print("return_error(): The number of args passed does not match the error template for " +
      "error code: " + error_template[2] + ". (Expected " + error_template[0] +
      ", received " + len(args) + ")");
    return IF_ERROR;
  }

  # Print error if verbose.
  if (IF_VERBOSE_ERRORS) err_print(vsprintf(args:args, format:error_template[1]));

  return error_template[2];
}

# Copy of build_url() in http_misc_func.inc to avoid dependency
# requirement.
function build_url2(port, host, qs, username, password)
{
  local_var t, url, p, n;

  t = get_port_transport(port);
  p = "";
  if (t > ENCAPS_IP)
  {
    url = "https://";
    if (port != 443) p = strcat(':', port);
  }
  else
  {
    url = "http://";
    if (port != 80) p = strcat(':', port);
  }

  if (strlen(host) > 0)
    n = host;
  else
  {
    if (get_kb_item("DNS/invalid_hostname"))
    n = get_host_ip();
    else
    {
      n = get_host_name();
      if (n =~ "^([0-9]+\.)+in-addr\.arpa$")
      n = get_host_ip();
    }
  }

  if (! isnull(username) || ! isnull(password))
  {
    url += username;
    if (! isnull(password))
    url += ":" + password;
    url += "@";
  }
  url = strcat(url, n, p);
  if (strlen(qs) > 0 && qs[0] == '/') url = strcat(url, qs);
  else url = strcat(url, '/', qs);
  return url;
}
