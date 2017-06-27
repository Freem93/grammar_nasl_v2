#TRUSTED 3cd40b32a4932fb87787b7c6fb1214348e65952215a3bee7b9a30ada6451b503741db8d978dab83ce19a92c09cfe0d9d341d70c8f0cd9edd7496c289d7d9e50863363a6f9d19d5b7b02420c814f9fe5d319c12bc6195299efd4bc9d2757e570e00d2dbea3c3a74809b7803ec385bbd5373f03a6e342ed869250f1e25ddba7b628c781d6710930750b80a8fab5d407d041f5f59a342bf151a8a5a328204e0bc914711407294f0123524e9393ed195d258cca45d59aacd461e8361b70914403b9f1d45adb02a87d3ad0027d96733ae613e9bd245095c537e08a11c13edde3fd9ca026f51baa01255266cefa40d42c7cfa498ac37904c0f0e009e62dadbed820b93f4bc5d31c796cbbfe1524ae023cf1d944d924fda3bc7e461fec3838ae68280af6dc9a109cad9849ff728ed2490dcc99b8cb272a555f2e361ddb15adbff5f3970947cf19ebe8aa57e31472c2e7603b7b8780f98083e434b842cab5c81b46b6677f5b7a8a760c0f6cee57bf6eb3eac58cc2677a27fb4508704e57dec9b800ccab51a72d9cf5a2032d6b95d88e2ccebc74122cea185b79a3abd3cc0c37bd346ce51f934eefeb7a0b1a0460cff5c7c041dd0987a4ebad0cec3d8b4e2b69b89e99de11fb33274f91554372197036a674cc06c43fb7ea25c5fa999238a67bdee964f1e7662947218db87ed319629da79d3d3f5392601d99e5188295d28a5fd2e5893c9

###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
# @include misc_func.inc
#
###

##
# Name of the table where logs are stored.
##
global_var __SPAD_LOG_TABLE_NAME;
__SPAD_LOG_TABLE_NAME  = "logstore";

##
# For thread safety (some plugins call branch/fork)
##
global_var __SPAD_LOG_SQLDB_MUTEX;
__SPAD_LOG_SQLDB_MUTEX = __SPAD_LOG_TABLE_NAME + "_" + get_host_ip();

##
# Table definition for spad log table
#
# id      : log message id (integer auto increments)
# name    : log file name (128 CHAR) used when attached as a file, should be unique
#           for a logging session e.g. "ssh_get_info.log" or "virus_scanner_debug.log"
#           defaults to SCRIPT_NAME.log. This column is indexed.
# time    : time stamp for message, will be pre-appended to message when log created
# message : log message (unrestricted TEXT)
##
global_var __SPAD_LOG_TBL_SQL;

##
# SQL to insert a new log message
##
global_var __SPAD_LOG_INS_SQL;

##
# SQL to get unique log names
##
global_var __SPAD_LOG_NAM_SQL;

##
# SQL to check if table is created
##
global_var __SPAD_LOG_CHK_SQL;

##
# SQL to get text / time data for single log
##
global_var __SPAD_LOG_TXT_SQL;

__SPAD_LOG_INS_SQL = "INSERT INTO "+__SPAD_LOG_TABLE_NAME+" (name,message) VALUES(?,?)";
__SPAD_LOG_NAM_SQL = "SELECT DISTINCT name FROM "+__SPAD_LOG_TABLE_NAME;
__SPAD_LOG_CHK_SQL = "SELECT COUNT(*) as cnt FROM sqlite_master WHERE type='table' AND name='" +__SPAD_LOG_TABLE_NAME+"'";
__SPAD_LOG_TXT_SQL = "SELECT time,message FROM "+__SPAD_LOG_TABLE_NAME+" WHERE name=? ORDER BY time";
__SPAD_LOG_TBL_SQL =
  "CREATE TABLE IF NOT EXISTS "+__SPAD_LOG_TABLE_NAME+" (" +
    "id      INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
    "name    CHAR(128) NOT NULL ," +
    "time    DATETIME DEFAULT current_timestamp, " +
    "message TEXT" +
  "); " +
  "CREATE INDEX IF NOT EXISTS logstore_name_idx ON "+__SPAD_LOG_TABLE_NAME+"(name)";

##
# Adds log message specified by param 'message' to the
# log handle / file specified by param 'name'.
#
# @param message string required - message to log
# @param name    string optional - name of the log handle to log message
#                                  defaults to <SCRIPT_NAME>.log
#
# @remark Returns immediately if kb item 'global_settings/enable_plugin_debugging'
#         is not set.
#
# @remark If you are running in "CLI Mode" messages will be displayed directly
#         to the STDOUT and name will be ignored entirely.
#
# @remark It's highly recommended if you're logging in a plugin that branches / 
#         forks to not use the default name or to pre-append a thread specific
#         identifier to message, e.g.:
#
#            port = branch(list_of_ports)
#            spad_log(message:"("+port+") Opening connection ...");
#
#         Remember that functions like get_kb_item and get_single_install can
#         branch depending on the structure of the KB, its up to you to decide
#         if thread specific logging is appropriate for your logging needs in
#         these situations.
##
function spad_log(message,name)
{
  # Skip if plugin logging not enabled
  if(!get_kb_item("global_settings/enable_plugin_debugging"))
    return;

  # Set default values
  if(isnull(name))
    name = ((SCRIPT_NAME - ".nasl") - ".nbin") + ".log";
  # Catch dev mistakes
  if(typeof(name) !~ '(data|string)')
  {
    err_print("Parameter 'name' is null or an invalid type.");
    return;
  }
  if(isnull(message) || typeof(message) !~ '(data|string)')
  {
    err_print("Parameter 'message' is null or an invalid type.");
    return;
  }

  # If we're not running in CLI mode log to spad db
  if(!isnull(get_preference("plugins_folder")))
  {
    _spad_log_to_db(message:message,name:name);
  }
  # If we are in CLI mode show message directly
  else
  {
    display(message);
    if(message !~ '\n$')
      display('\n');
  }
}

##
# Returns a structure that can be attached with security_report_with_attachments
##
function spad_log_get_report_attachments()
{
  local_var names,row,msgs,logs,txt,lidx;

  if(!_spad_log_has_inited())
    return NULL;

  names = query_scratchpad(__SPAD_LOG_NAM_SQL);

  if(empty_or_null(names))
    return NULL;

  logs = make_list();
  lidx = 0;
  foreach row (names)
  {
    if(isnull(row['name']))
      continue;

    txt = _spad_log_get_txt(name:row['name']);

    if(isnull(txt))
      continue;

    logs[lidx] = make_array();
    logs[lidx]["type" ] = "text";
    logs[lidx]["name" ] = row['name'];
    logs[lidx]["value"] = txt;
    lidx += 1;
  }
  return logs;
}

##
# Adds log message specified by param 'message' to the
# log handle / file specified by param 'name'. Does
# the scratch pad database interaction only.
#
# @param message string required - message that to log
# @param name    string required - name of the log handle to log message
#
##
function _spad_log_to_db(message,name)
{
  if(typeof(name) !~ '(data|string)')
  {
    err_print("Parameter 'name' is null or an invalid type.");
    return;
  }
  if(isnull(message) || typeof(message) !~ '(data|string)')
  {
    err_print("Parameter 'message' is null or an invalid type.");
    return;
  }

  if(!_spad_log_has_inited())
    _spad_log_init();

  query_scratchpad(__SPAD_LOG_INS_SQL,name,message);
}

##
# Get the log text for particular log
#
# @param name string required - name of the log to get the text of
#
# @remark a new line if always added to the end of messages if one
#         is not already present
##
function _spad_log_get_txt(name)
{
  local_var ret,row,txt;

  if(isnull(name) || typeof(name) !~ '(data|string)')
  {
    err_print("Parameter 'name' is null or an invalid type.");
    return NULL;
  }
  
  ret = query_scratchpad(__SPAD_LOG_TXT_SQL, name);

  if(empty_or_null(ret))
    return NULL;
  txt = NULL;
  foreach row (ret)
  {
    txt += "["+row['time']+"] "+row["message"];
    if(txt !~ '\n$') txt += '\n';
  }
  return txt;
}

##
# Creates the necessary SQLite tables for logging
##
function _spad_log_init()
{
  query_scratchpad(__SPAD_LOG_TBL_SQL);
}

##
# Checks to see the log structures have been initialized
##
function _spad_log_has_inited()
{
  local_var ret;

  ret = query_scratchpad(__SPAD_LOG_CHK_SQL);

  if(isnull(ret) || ret[0]["cnt"] == 0)
    return FALSE;
  return TRUE;
}
