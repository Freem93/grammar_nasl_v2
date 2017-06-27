##
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
# smb_reg_query.inc
# $Revision: 1.13 $
#
# This include file provides some wrapper functions for accessing
# registry data.
#
# @include global_settings.inc - err_print(), debug_print()
# @include misc_func.inc - get_kb_item_or_exit() used in registry_init()
# @include smb_reg.inc - for the underlying registry functions and constants
# @include smb_hotfixes_fcheck.inc - for SMB connection/login
##

# from smb_hotfixes_fcheck.inc, needed by get_registry_values() for connecting to the remote host
global_var hcf_init, HCF_OK;

##
# Connects to the registry share
#
# @param full_access_check if not FALSE, calls exit() if any "SMB/registry_full_access" is not set.
# @remark this function exits if it fails for any reason
# @remark this connection should be closed using either [close_registry] (no args) or [smb_hotfixes_fcheck#hotfix_check_fversion_end]
##
function registry_init(full_access_check)
{
  local_var login, pass, domain, r;

  if (isnull(full_access_check) || full_access_check != FALSE)  get_kb_item_or_exit("SMB/registry_full_access");

  if (hcf_init == 0 && hotfix_check_fversion_init() != HCF_OK)
    exit(1, 'registry_init(): hotfix_check_fversion_init() failed');

  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();

  r = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
  if ( r != 1 )
  {
    NetUseDel();
    exit(1, 'Can\'t connect to IPC$ share.');
  }
}

##
# Disconnects from the registry
#
# @param close specify whether or not the underlying connection is also closed. TRUE by default
# @remark when the caller does not pass close:FALSE this does the same thing as [smb_hotfixes_fcheck#hotfix_check_fversion_end]
##
function close_registry(close)
{
  if (isnull(close) || (close == TRUE))
    return hotfix_check_fversion_end();

  return NetUseDel(close:FALSE);
}

##
# connects to the given registry hive
#
# @param hive the registry hive to connect to. this must be one of the HKEY_* constants
# @param exit_on_fail if not NULL/FALSE, calls exit() if any error is encountered
# @remark this function assumes a connection to IPC$ has already been established
#
# @return a handle to 'hive', or
#         NULL if the connection failed and exit_on_fail is NULL or FALSE
##
function registry_hive_connect(hive, exit_on_fail)
{
  local_var msg, ret;

  if (isnull(hive))
  {
    msg = 'registry_hive_connect(): missing required arg "hive"';

    if (exit_on_fail)
    {
      hotfix_check_fversion_end();
      exit(1, msg);
      # never reached
    }
    
    err_print(msg);
    return NULL;
  }

  ret = RegConnectRegistry(hkey:hive);
  if (isnull(ret) && exit_on_fail)
  {
    hotfix_check_fversion_end();
    exit(1, "Failed to connect to the remote registry.");
  }
  return ret;
}

##
# Gets all the subkeys contained in a registry key
# 
# @param  handle  handle to the registry hive to query.
# @param  key     the full path of the registry key to query, without the preceding hive name
# @param  wow     an optional boolean to check the wow6432 registry hive
#
# @return a list of subkeys contained in 'key', or
#         an array if the wow parameter is TRUE or
#         NULL if any errors were encountered
##
function get_registry_subkeys(handle, key, wow)
{
  local_var subkeys, subkeys6432, key6432, key_h, info, i, subkey;
  subkeys = make_list();
  subkeys6432 = make_list();

  if (isnull(handle))
  {
    err_print('get_registry_subkeys(): missing required arg "handle"');
    return NULL;
  }
  if (isnull(key))
  {
    err_print('get_registry_subkeys(): missing required arg "key"');
    return NULL;
  }

  key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
  if (isnull(key_h))
    return NULL;

  info = RegQueryInfoKey(handle:key_h);
  if (isnull(info)) return NULL;

  for (i = 0; i < info[1]; i++)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (isnull(subkey)) return NULL;
    subkeys = make_list(subkeys, subkey);
  }

  RegCloseKey(handle:key_h);

  if (wow)
  {
    # Make sure the registry is HKLM and the WoW6432 node is available
    if (handle[3] == HKEY_LOCAL_MACHINE && get_kb_item("SMB/WoW"))
    {
      key6432 = ereg_replace(pattern:"^SOFTWARE\\(.*)", string:key, replace:"SOFTWARE\\Wow6432Node\\\1", icase:TRUE);
      key_h = RegOpenKey(handle:handle, key:key6432, mode:MAXIMUM_ALLOWED, wow:FALSE);
      if (!isnull(key_h))
      {
        info = RegQueryInfoKey(handle:key_h);
        if (!isnull(info))
        {
          for (i=0; i < info[1]; i++)
          {
            subkey = RegEnumKey(handle:key_h, index:i);
            if (!isnull(subkey))
              subkeys6432 = make_list(subkeys6432, subkey);
          }
        }
        RegCloseKey(handle:key_h);
      }
    }
    return make_array(key, subkeys, key6432, subkeys6432);
  }
  return subkeys;
}

##
# Gets the list of values from a registry key
#
# @param  handle  handle to the registry hive to query.
# @param  entries a list of value entries contained in 'key' to query. cannot contain any keys or subkeys.
# @param  key     the full path of the registry key to query, without the preceding hive name
#
# @return   a hash where each key is an element in 'values' and the value is the data pulled from the registry.
#           if any elements in 'values' were not found in the registry, they're not included in this hash.
#           if no elements in 'values' were found, returns NULL
##
function get_values_from_key(handle, entries, key)
{
  local_var items, results, keylen, entry, name, value, ret;
  items = make_list();
  ret = make_array();

  if (isnull(handle))
  {
    err_print('get_values_from_key(): missing required arg "handle"');
    return NULL;
  }
  if (isnull(entries))
  {
    err_print('get_values_from_key(): missing required arg "entries"');
    return NULL;
  }
  if (isnull(key))
  {
    err_print('get_values_from_key(): missing required arg "key"');
    return NULL;
  }

  # add a trailing backslash to the key name if it isn't already there
  keylen = strlen(key);
  if (keylen > 0 && key[keylen - 1] != "\")
    key += "\";

  foreach entry (entries)
    items = make_list(items, key + entry);

  results = get_registry_values(handle:handle, items:items);
  if (isnull(results) || max_index(keys(results)) == 0)
    return NULL;

  # reformat hash so the registry key is removed from the hash key name
  # e.g. SOFTWARE\foo\bar\baz => 1234
  # becomes
  # baz => 1234
  foreach name (keys(results))
  {
    value = results[name];
    name -= key;
    ret[name] = value;
  }

  return ret;
}

##
# queries the registry for the given registry value
#
# @param  handle handle to the registry hive to query.
# @param  item  the full path of the registry item to query, without the preceding hive name.  this must not be a registry key.
#
#               The registry key and item to query are inferred from the path - the last element is assumed to be the value
#               name to query, and everything preceding it is assumed to be the key.
#               e.g. providing an item of 'foo\bar\baz' causes this function to query 'baz' in the 'foo\bar' key.
#               In order to get the default value associated with a key, use a trailing slash, e.g.,
#               SOFTWARE\Microsoft\FooApp\ will retrieve the (Default) value in the FooApp subkey
# @return      the desired registry value if it was found successfully, or
#              NULL otherwise
##
function get_registry_value(handle, item)
{
  local_var ret, value;

  if (isnull(handle))
  {
    err_print('get_registry_value(): missing required arg "handle"');
    return NULL;
  }
  if (isnull(item))
  {
    err_print('get_registry_value(): missing required arg "item"');
    return NULL;
  }

  ret = get_registry_values(handle:handle, items:make_list(item));
  if (isnull(ret) || max_index(keys(ret)) == 0)
    return NULL;
    
  ret = make_list(ret);
  value = ret[0];

  return value;
}

##
# queries the registry for multiple registry values
#
# @param  handle handle to the registry hive to query.
# @param  items  a list of elements containing the full path of each registry item to query, without the preceding hive name.
#
#                The registry key and item to query are inferred from the path - the last element is assumed to be the value
#                name to query, and everything preceding it is assumed to be the key.
#                e.g. providing an item of 'foo\bar\baz' causes this function to query 'baz' in the 'foo\bar' key.
#                In order to get the default value associated with a key, use a trailing slash, e.g.,
#                SOFTWARE\Microsoft\FooApp\ will retrieve the (Default) value in the FooApp subkey
# @return      the desired registry values if they were found successfully, or
#              NULL otherwise.  a non-NULL return value is a hash whose keys are
#              the original elements of 'items', and the values are the
#              corresponding entry values
##
function get_registry_values(handle, items)
{
  local_var item, match, key, open_key, key_h, name, value, ret;
  ret = make_array();

  if (isnull(handle))
  {
    err_print('get_registry_values(): missing required arg "handle"');
    return NULL;
  }
  if (isnull(items))
  {
    err_print('get_registry_values(): missing required arg "items"');
    return NULL;
  }

  open_key = NULL;  # the currently open key
  key_h = NULL;

  # Query the registry for the specified entries.
  # "items" is sorted to ensure entries with like keys are grouped together
  foreach item (sort(items))
  {
    # extract the registry key and entry name
    match = eregmatch(string:item, pattern:'^(.*)\\\\([^\\\\]+)?$');

    # the regex should only fail if the caller provides invalid input
    if (!match)
    {
      debug_print('error parsing registry entry: ' + item);
      continue;
    }

    key = match[1];
    name = match[2];

    # avoid closing and reopening the same key multiple times
    if (key != open_key)
    {
      if (!isnull(key_h))
        RegCloseKey(handle:key_h);
      key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
      open_key = key;
    }

    if (!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:name);
      if (!isnull(value))
        ret[item] = value[1];
    }
    else
      debug_print('Unable to open key: ' + key);
  }

  if (!isnull(key_h))
    RegCloseKey(handle:key_h);

  return ret;
}

##
# get a set of values listed in a key
#
# @param  handle  handle to the registry hive to query.
# @param  key     the full path of the registry key to query, without the preceding hive name 
#
# @remark all keys int he array returned are set to lowercase to prevent case issues
#
# @return an array with name key and value index, or
#         NULL if any errors were encountered
##
function get_reg_name_value_table(handle ,key)
{
  local_var ret, key_h, info, i, value, value_info, value_data, name_data_set;

  if (isnull(handle))
  {
    err_print('get_reg_name_value_table(): missing required arg "handle"');
    return NULL;
  }
  if (isnull(key))
  {
    err_print('get_reg_name_value_table(): missing required arg "key"');
    return NULL;
  }

  ret = make_array();

  key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
  if (isnull(key_h)) return NULL;

  info = RegQueryInfoKey(handle:key_h);
  if (isnull(info)) return NULL;

  value_info = RegQueryValue(handle:key_h, item:"");
  if (!isnull(value_info[1])) ret["(default)"] = value_info[1];

  for (i=0;i<info[0];i++)
  {
    value = RegEnumValue(handle:key_h, index:i);
    if (isnull(value[1])) continue;

    value_info = RegQueryValue(handle:key_h, item:value[1]);
    if (isnull(value_info[1])) continue;

    ret[tolower(value[1])] = value_info[1];
  }

  return ret;
}

##
# Generic query to gather hku values in an easy way
#
# @param [key:string] the key path after HKEY_USER\<user>\
# @param [decode:bool] decode the values into raw, ascii, hex return values
# @param [reg_init:bool] initialize and close registry. Default TRUE
#
# @return array of results
##
function get_hku_key_values(key, decode, reg_init, resolve_sid)
{
  local_var hku, hku_list, user, res, ret, k, username;

  if (isnull(reg_init)) reg_init = TRUE;
  if (isnull(resolve_sid)) resolve_sid = TRUE;

  ret = make_array();

  if (reg_init)
  {
    registry_init();
  }

  hku = registry_hive_connect(hive:HKEY_USERS);
  if (isnull(hku))
  {
    if (reg_init) close_registry();
    return NULL;
  }

  hku_list = get_registry_subkeys(handle:hku, key:'');
  foreach user (hku_list)
  {
    res = get_reg_name_value_table(handle:hku, key:user + key);
    if (!empty_or_null(res))
    {
      if (decode)
      {
        foreach k (keys(res))
        {
          res[k] = get_raw_ascii_hex_values(val:res[k]);
        }
      }

      if (resolve_sid)
      {
        username = get_hku_usernames(handle:hku, sid:user);
      }

      if (isnull(username)) ret[user] = res;
      else ret[username] = res;
    }
  }

  RegCloseKey(handle:hku);

  if (reg_init)
  {
    close_registry();
  }

  return ret;
}

##
# get the username for the HKEY_USER key
#
# @param [username:string] each result from get_registry_subkeys(handle:hku, key:'');
#
# @return string, the username, NULL on failure
##
function get_hku_usernames(handle, sid)
{
  local_var res, key, username, domain;

  username = get_kb_item('HKEY_USERS\\'+sid);
  if (isnull(username))
  {
    key = "\\Volatile Environment\\";
    res = get_reg_name_value_table(handle:handle, key:sid + key);

    username = res['username'];
    domain = res['userdnsdomain'];
    if (!isnull(username))
    {
      if (!isnull(domain))
      {
        username = domain + '\\' + username;
      }
      set_kb_item(name:'HKEY_USERS\\'+sid, value:username);
    }
  }

  return username;
}

##
# Generic query to gather hku subkeys in an easy way
#
# @param [key:string] the key path after HKEY_USER\<user>\
# @param [reg_init:bool] initialize and close registry. Default TRUE
#
# @return array of results
##
function get_hku_keys(key, reg_init)
{
  local_var hku, hku_list, user, res, ret;

  if (isnull(reg_init))
  {
    reg_init = TRUE;
  }

  ret = make_array();

  if (reg_init)
  {
    registry_init();
  }

  hku = registry_hive_connect(hive:HKEY_USERS);
  if (isnull(hku))
  {
    if (reg_init) close_registry();
    return NULL;
  }

  hku_list = get_registry_subkeys(handle:hku, key:'');
  foreach user (hku_list)
  {
    res = get_registry_subkeys(handle:hku, key:user + key);
    if (!empty_or_null(res))
    {
      ret[user] = res;
    }
  }

  RegCloseKey(handle:hku);

  if (reg_init)
  {
    close_registry();
  }

  return ret;
}
