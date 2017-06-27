###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# <at:var at:name="NOGPL" />
#
# browser.inc
# $Revision: 1.1 $
#
# @include audit.inc
# @include global_settings.inc
# @include misc_func.inc
###

##
# Check if the browser_addons table exists
#
# @return TRUE or FALSE
##
function _addons_table_exists()
{
  if(isnull(query_scratchpad("SELECT name FROM sqlite_master WHERE type='table' AND name='browser_addons';")))
    return FALSE;
  else
    return TRUE;
}

##
# Build the browser_addons table
##
function _build_addons_table()
{
  query_scratchpad(
    "CREATE TABLE IF NOT EXISTS browser_addons(
    user text,
    browser text,
    type text,
    name text,
    description text,
    version text,
    path text,
    install_date text,
    update_date text,
    extra text,
    PRIMARY KEY(user, browser, path)
  );");
}

##
# Save information about a browser add-on to the KB
#
# @param user         User account that the add-on is installed for; use 'All' or
#                     'All Users' for add-ons that are not account-specific; will
#                     default to to 'unknown' if empty or NULL (optional, but
#                     recommended for reporting)
# @param browser      Name of the browser that the add-on is installed for (required)
# @param type         Type of add-on (e.g. Extension, Plugin, Service); custom
#                     types are OK (required)
# @param name         Name of the add-on (e.g. Facebook, uBlock Origin); will default
#                     to 'unknown' if empty or NULL (optional, but strongly recommended
#                     if a name is available)
# @param desc         Description of the add-on (optional)
# @param path         Path to the add-on (required)
# @param ver          Version of the add-on (optional)
# @param install_date Installation data of the add-on (optional)
# @param update_date  Last updated or last modified date of the add-on (optional)
# @param extra        Array of additional information about the add-on, with report field
#                     names as keys, e.g. extra['ID'] = 'firefox@getpocket.com' (optional)
# @param exit_on_fail TRUE or FALSE; defaults to TRUE; determines if the function
#                     will exit when an error occurs or return the error. (optional)
#
# @return array       An array consisting of an 'error' key with value NULL for success
#                     or an error message for failure
##
function save_browser_addon(user, browser, type, name, desc, path, ver, install_date, update_date, extra, exit_on_fail)
{
  local_var lbrowser, ltype;

  if(!_addons_table_exists())
    _build_addons_table();

  # Set exit_on_fail default to TRUE if not provided
  if(isnull(exit_on_fail))
    exit_on_fail = TRUE;

  # Validate arguments
  if(empty_or_null(user))
    user = "unknown";
  else if (tolower(user) == 'all' || tolower(user) == 'all users')
    user = 'All Users';

  if(empty_or_null(browser))
  {
    if(exit_on_fail) audit(AUDIT_FN_FAIL, "save_browser_addon","Argument 'browser' is empty or NULL.");
    else return make_array('error',"Argument 'browser' is empty or NULL.");
  }
  else
  {
    # Standardize for KB
    lbrowser = tolower(browser);
    if(lbrowser == 'firefox') browser = 'Firefox';
    else if (lbrowser == 'chrome') browser = 'Chrome';
  }

  if(empty_or_null(type))
  {
    if(exit_on_fail) audit(AUDIT_FN_FAIL, "save_browser_addon","Argument 'type' is empty or NULL.");
    else return make_array('error', "Argument 'type' is empty or NULL.");
  }
  else
  {
    # Standardize for KB
    ltype = tolower(type);
    if (ltype =~ '^extension(s)?$') type = 'Extension';
    else if (ltype =~ '^plugin(s)?$') type = 'Plugin';
    else if (ltype =~ '^service(s)?$') type = 'Service';
    else if (ltype =~ '^add(-)?on(s)?$') type = 'Add-on';
  }

  if(empty_or_null(name))
    name = "unknown";

  if(empty_or_null(path))
  {
    if(exit_on_fail) audit(AUDIT_FN_FAIL, "save_browser_addon","Argument 'path' is empty or NULL.");
    else return make_array('error', "Argument 'path' is empty or NULL.");
  }

  if(!isnull(extra))
  {
    if(typeof(extra) != 'array')
    {
      if(exit_on_fail) audit(AUDIT_FN_FAIL, "save_browser_addon","Argument 'extra' is not an array.");
      else return make_array('error', "Argument 'extra' is not an array.");
    }
    extra = serialize(extra);
  }

  # Use INSERT OR IGNORE in case this user/browser/path key combo has already been saved
  query_scratchpad(
    "INSERT OR IGNORE INTO browser_addons VALUES(
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    user, browser, type, name, desc, ver, path, install_date, update_date, extra);

  # Mark in the KB that there are values saved for this browser and add-on type
  replace_kb_item(name:'Browser/'+browser+'/'+type, value:TRUE);

  return make_array('error', NULL);
}

##
# Retrieve information about browser add-ons from the KB
#
# @param browser      Name of the browser to retrieve add-on information about. Use 'all'
#                     for all browsers. Defaults to 'all' if empty or NULL. (optional)
# @param type         Type of add-on (e.g. Extension, Plugin, Service). Use 'all' for
#                     all add-on types. Defaults to 'all' if empty or NULL. (optional)
# @param name         Name of the add-on (e.g. Facebook, uBlock Origin). Inserted into
#                     scratchpad query as "name LIKE '%<name>%'". Use 'all' for all
#                     names. Defaults to 'all' if empty or NULL. (optional)
# @param exit_on_fail TRUE or FALSE; defaults to TRUE; determines if the function
#                     will exit when an error occurs or return the error. (optional)
#
# @return array       An array consisting of an 'error' key with value NULL for success
#                     or an error message for failure, and if successful, key 'addons'
#                     and an array of information about matching add-ons. addons format:
#                     addons[0: <array>][1: <array>] where each array contains key/value
#                     pairs of information about a single add-on.
#
# @remark The 'browser', 'name', and 'type' arguments *must* not be controlled by
#         anything the user controls, as they are not used in a prepared statement.
##
function get_browser_addons(browser, type, name, exit_on_fail)
{
  local_var app_name, substrings, i, query, addon_data, addon, extra, key;

  # Set defaults
  if(isnull(exit_on_fail))
    exit_on_fail = TRUE;

  # Build app_name for audits and substrings for query
  i=0;
  substrings = make_list();

  if(empty_or_null(browser) || tolower(browser) == 'all')
    app_name = 'Browser';
  else
  {
    app_name = browser;
    substrings[i] = "browser LIKE '%" + browser + "%'";
    i++;
  }

  if(empty_or_null(type) || tolower(type) == 'all')
    app_name += ' add-on';
  else
  {
    if (tolower(type) =~ '^add(-)?on(s)?$') type = 'Add-on';
    app_name += ' ' + type;
    substrings[i] = "type LIKE '%" + type + "%'";
    i++;
  }

  if(empty_or_null(name) || tolower(name) == 'all')
    app_name = "A " + app_name;
  else
  {
    app_name += ' ' + name;
    substrings[i] = "name LIKE '%" + name + "%'";
    i++;
  }

  # If we haven't saved any add-ons, audit or return
  if(!_addons_table_exists())
  {
    if(exit_on_fail) audit(AUDIT_NOT_INST, app_name);
    else return make_array('error', app_name + " does not appear to be installed.");
  }

  query = "SELECT * FROM browser_addons";
  if (i > 0)
    query += " WHERE (" + join(substrings, sep:' AND ') + ")";
  query += " ORDER BY user ASC, browser ASC, type ASC;";

  addon_data = query_scratchpad(query);
  if(max_index(addon_data) < 1)
  {
    if(exit_on_fail) audit(AUDIT_NOT_INST, app_name);
    else return make_array('error', app_name + " does not appear to be installed.");
  }

  for (i=0; i < max_index(addon_data); i++)
  {
    if(!empty_or_null(addon_data[i]['extra']))
    {
      extra = deserialize(addon_data[i]['extra']);
      foreach key (sort(keys(extra)))
        addon_data[i][key] = extra[key];
      delete_element(var:addon_data[i], idx:'extra');
    }
  }

  return make_array('error', NULL, 'addons', addon_data);
}

##
# Report information about browser add-ons by using get_browser_addons() to retrieve
# information from the KB
#
# @param browser      Name of the browser to retrieve add-on information about. Use 'all'
#                     for all browsers. Defaults to 'all' if empty or NULL. (optional)
# @param type         Type of add-on (e.g. Extension, Plugin, Service). Use 'all' for
#                     all add-on types. Defaults to 'all' if empty or NULL. (optional)
# @param name         Name of the add-on (e.g. Facebook, uBlock Origin). Inserted into
#                     scratchpad query as "name LIKE '%<name>%'". Use 'all' for all
#                     names. Defaults to 'all' if empty or NULL. (optional)
# @param port         Port number to report the plugin output on
# @param exit_on_fail TRUE or FALSE; defaults to TRUE; determines if the function
#                     will exit when an error occurs or return the error
#
# @return array       An array consisting of an 'error' key with value NULL for success
#                     or an error message for failure
##
function report_browser_addons(browser, type, name, port, exit_on_fail)
{
  local_var data, addon, key;
  local_var current_user, current_browser, current_type;
  local_var report_str, report_items, ordered_fields, i;

  data = get_browser_addons(browser:browser, type:type, name:name, exit_on_fail:exit_on_fail);

  # If exit_on_fail is FALSE get_browser_addons() may have returned an error,
  # if so, pass through the error
  if(!isnull(data['error']))
    return data;

  data = data['addons'];

  if(empty_or_null(port)) port = 0;

  # Initialize header
  current_user = data[0]['user'];
  current_browser = data[0]['browser'];
  current_type = data[0]['type'];

  report_str =
    '\nUser : ' + current_user +
    '\n|- Browser : ' + current_browser +
    '\n  |- ' + current_type + ' information :\n';

  foreach addon (data)
  {
    # Add headers when switching to a new user, browser, or type
    if (addon['user'] != current_user)
    {
      current_user = addon['user'];
      current_browser = addon['browser'];
      current_type = addon['type'];
      report_str += '\nUser : ' + current_user;
      report_str += '\n|- Browser : ' + current_browser;
      report_str += '\n  |- ' + current_type + ' information :\n';
    }
    else if (addon['browser'] != current_browser)
    {
      current_browser = addon['browser'];
      current_type = addon['type'];
      report_str += '\n|- Browser : ' + current_browser;
      report_str += '\n  |- ' + current_type + ' information :\n';
    }
    else if (addon['type'] != current_type)
    {
      current_type = addon['type'];
      report_str += '\n  |- ' + current_type + ' information :\n';
    }

    # Remove elements as they are used
    delete_element(var:addon, idx:'user');
    delete_element(var:addon, idx:'browser');
    delete_element(var:addon, idx:'type');

    report_items = make_array('  Name', addon['name']);
    ordered_fields = make_list('  Name');
    delete_element(var:addon, idx:'name');

    i = 1;

    if(!empty_or_null(addon['description']))
    {
      report_items['  Description'] = addon['description'];
      ordered_fields[i] = '  Description';
      delete_element(var:addon, idx:'description');
      i++;
    }
    if(!empty_or_null(addon['version']))
    {
      report_items['  Version'] = addon['version'];
      ordered_fields[i] = '  Version';
      delete_element(var:addon, idx:'version');
      i++;
    }
    if(!empty_or_null(addon['install_date']))
    {
      report_items['  Install Date'] = addon['install_date'];
      ordered_fields[i] = '  Install Date';
      delete_element(var:addon, idx:'install_date');
      i++;
    }
    if(!empty_or_null(addon['update_date']))
    {
      report_items['  Update Date'] = addon['update_date'];
      ordered_fields[i] = '  Update Date';
      delete_element(var:addon, idx:'update_date');
      i++;
    }
    if(!empty_or_null(addon['path']))
    {
      report_items['  Path'] = addon['path'];
      ordered_fields[i] = '  Path';
      delete_element(var:addon, idx:'path');
      i++;
    }

    if(max_index(keys(addon)) > 0)
    {
      foreach key (sort(keys(addon)))
      {
        if(!empty_or_null(addon[key]))
        {
          report_items['  '+key] = addon[key];
          ordered_fields[i] = '  '+key;
          i++;
        }
      }
    }

    report_str += report_items_str(report_items:report_items, ordered_fields:ordered_fields);

  } # End loop through individual add-ons

  security_report_v4(port:port, extra:report_str, severity:SECURITY_NOTE);
  return make_array('error', NULL);
}