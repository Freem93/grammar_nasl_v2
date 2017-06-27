#TRUSTED a7e7dceb87be8b5cae891481c3de24592d33dbc643934b1195b06c2183c302d0a1151efaa4e4dca3d13e58f437dfd9ca4e9de48b4fdaf8ee72b5fb091208a2e9ac01eedf7ca8c791df37737383ebfb2fd19ce4a667f33b068f0023ff7175ac18d1e39d44d4c2dd6cccdf19b57ca25f10646282c76441b79c70d912fe7b337c140041d056fd8ae549c2c0aab59b30e5648a7bf9263821f252f27d8bb8fda750f605afc666f34483a3b49d4f134bedf7af57105d1fb207272f6860ce85c3a90a0d97a6d1668c202a9c823325759483da3c189610418c194a94db68ff35098154b7521322f25d29e4fdcd2070e5798a3bf7aba9d636928b5ccbcef68eaab8517161bbae969d3f2a8fafd234fcd817f917b5251afc7091bbb909ebc84b418d68da8f995dd58ffb9b3db81119131f8cb8bbdaa07ea050a1297cd275e366b1db72f6974db686e9acd01fe7cce508e0142dd2ae0142dc25c5847bc406ff9017ae49d9a50db230889e6a305d31096db8fc3508fe2976189b6d38a60b1e4a20b29fb6bfb9e0ff96e41e076930428ded9298a3549e9b0d293bfff3cc88de4ecbc4200c010a6152392831654dc92af1f3f4c1c7f3927e10bab174f475b11c138b8c5ee946e9fa5e6b001801ca1dc5269b65f74cad10c19bdd17e837cd5fd211187b7bc7cfc5a2cdc54ec85a47531b0a6e8cfd076583f48212c2916f74b4448032085d2f71bc
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
# smb_glue.inc
# Revision: 1.23
#

# SMB 'transports'
SMB_DIRECT    = 1;  # Remote scan with direct, separate SMB connections
SMB_LOCAL     = 2;  # Local scan with Nessus Agent
SMB_SERVICE   = 3;  # Remote scan with SMB service (i.e., Connection Agent)
SMB_NSX       = 4;  # Local scan with NSX

SMB_UNKNOWN         = 0x80000001; # Unknown SMB transport
SMB_NOT_IMPLEMENTED = 0x80000002; # SMB transport not implemented
SMB_NOT_SUPPORTED   = 0x80000003; # Engine doesn't support local Windows checks
                                  # i.e., Unix Local Agent

global_var UNIT_TESTING = FALSE;
global_var TEST_TRANSPORT = SMB_LOCAL;

function _smb_transport()
{
  local_var env;

  if (UNIT_TESTING) return TEST_TRANSPORT;
  # SMB plugins are run by the Local Nessus Agent
  if(defined_func("nasl_environment") && nasl_level() >= 6000)
  {
    #env   = nasl_environment(flags: ENV_APP);
    env   = nasl_environment();

    # Windows local agent
    if(env["product"] == PRODUCT_WIN_AGENT)
    {
      return SMB_LOCAL;
    }
    # Normal Nessusd
    else if (env["product"] == PRODUCT_NESSUSD)
    {
      return SMB_DIRECT;
    }
    # Nessusd on NSX
    else if (env["product"] == PRODUCT_NESSUSD_NSX)
    {
      return SMB_NSX;
    }
    # Unix local agent
    # Windows credentialed checks are not run on Unix agent?
    if(env["product"] == PRODUCT_UNIX_AGENT)
    {
      return NULL; # or SMB_NOT_SUPPORTED?
    }
    else return NULL;
  }

  #
  # Some way to identify SMB service
  #

  # Older nessusd doesn't support agent/NSX mode or SMB service
  return SMB_DIRECT;
}


##
# SMB session initialization
#
# @return TRUE/FALSE
# @remark
#   - Network based session calls open_sock_tcp()
#   - Non-network based session does not
##
function smb_session_init(smb2, timeout)
{
  local_var name, port, soc, transport;

  transport = _smb_transport();
  name = kb_smb_name();

  if (isnull(smb2))
  {
    if (isnull(get_kb_item("SMB/use_smb2")))
    {
      smb2 = TRUE;
    }
    else
    {
      smb2 = get_kb_item("SMB/use_smb2");
    }
  }

  if(transport == SMB_DIRECT)
  {
    port = kb_smb_transport();
    if (!get_port_state(port)) return FALSE;
    soc = open_sock_tcp(port);
    if (!soc) return FALSE;
    session_init(socket:soc, hostname:name, timeout: timeout, smb2: smb2);
  }
  else if (transport == SMB_LOCAL)
  {
    session_init(socket:NULL, hostname:name);
  }
  else if(transport == SMB_SERVICE)
  {
    return FALSE; # for now
  }
  else if(transport == SMB_NSX)
  {
    return FALSE; # for now
  }
  else return FALSE;

  return TRUE;

}


#-----------------------------------------------------------#
#     Wrappers for SMB network APIs (smb_net.inc)           #
#-----------------------------------------------------------#

##
#
# @return
#   1 = success
#   0 = share connection failed / invalid share name
#  -1 = login failed
# NULL if not SMB transport not implemented or not known
##
function NetUseAdd (login,password,domain,share,lm_hash,ntlm_hash)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_NetUseAdd(
      login:login,
      password:password,
      domain:domain,
      share:share,
      lm_hash: lm_hash,
      ntlm_hash: ntlm_hash);
  }
  # Use Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    local_var path;

    if(share)
    {
      # Convert share name to a local path
      # Note: winfile_localpath() will return NULL for IPC$
      path = winfile_localpath(share);
      if(tolower(share) != tolower('IPC$') && isnull(path))
        return 0;
      session_set_share_name(share:path);
    }

    return 1;
  }
  # Use SMB service
  else if(transport == SMB_SERVICE)
  {
  }
  # Use NSX
  else if(transport == SMB_NSX)
  {
  }

  return NULL;
}

##
#
# @return
#   1 = Success
#  -1 = smb_tree_disconnect() failed
# NULL if not SMB transport not implemented or not known
##
function NetUseDel (close)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_NetUseDel(close: close);
  }
  # Use Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    session_set_share_name(share:NULL);
    return 1;
  }
  # Use SMB service
  else if(transport == SMB_SERVICE)
  {
  }
  # Use NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}



#-----------------------------------------------------------#
#     Wrappers for SMB file APIs (smb_file.inc)             #
#-----------------------------------------------------------#

##
# @remark You must know if you are opening a file or a directory and use
#         FILE_ATTRIBUTE_NORMAL or FILE_ATTRIBUTE_DIRECTORY respectively.
#         Using FILE_ATTRIBUTE_NORMAL against a directory may succeed during an
#         SMB_DIRECT scan, but this is not permitted by the "native" CreateFile
#         and as a result will fail on the Windows agent.
# @return
#   ret[0] - File handle
#   ret[1] - SMB_DIRECT: 8-byte file size
#            SMB_LOCAL:  file name in full path
#   NULL on error
##
function CreateFile (file, desired_access, file_attributes, share_mode, create_disposition, create_options)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_CreateFile (
              file: file,
              desired_access: desired_access,
              file_attributes: file_attributes,
              share_mode:share_mode,
              create_disposition: create_disposition,
              create_options: create_options);
  }
  # Use Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    local_var path, handle;

    path  = session_get_share_name() + file;

    # Convert [MS-CIFS] Creation Disposition Constants to CreateFile() constants
    if(create_disposition == OPEN_EXISTING)
    {
      create_disposition = 3;
    }
    else if (create_disposition == OPEN_ALWAYS)
    {
      create_disposition = 4;
    }
    else if (create_disposition == CREATE_NEW)
    {
      create_disposition = 1;
    }
    else if (create_disposition == CREATE_ALWAYS)
    {
      create_disposition = 2;
    }
    else if (create_disposition == TRUNCATE_EXISTING)
    {
      create_disposition = 5;
    }
    # Default: OPEN_EXISTING
    else
    {
      create_disposition = 3;
    }

    #
    # CreateFile() doc:
    # To open a directory using CreateFile, specify the
    # FILE_FLAG_BACKUP_SEMANTICS flag as part of dwFlagsAndAttributes
    #
    if(file_attributes & FILE_ATTRIBUTE_DIRECTORY)
    {
      file_attributes = file_attributes | FILE_FLAG_BACKUP_SEMANTICS;
    }
    handle = winfile_create (
              file: path,
              desired_access: desired_access,
              file_attributes: file_attributes,
              share_mode:share_mode,
              create_disposition: create_disposition);

    if ( isnull(handle) ) return NULL;
    return make_list(handle, path);

  }
  # Use SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # Use NSX
  else if(transport == SMB_NSX)
  {
  }

  return NULL;
}

##
#
#
# @return
#     1     = Success
#     NULL  = Error
##
function CloseFile (handle)
{
  local_var ret, transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_CloseFile(handle: handle);
  }
  # Use Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    ret = close_handle(handle[0]);

    # close_handle() returns TRUE/FALSE
    if(ret == FALSE) return NULL;
    return ret;
  }
  # Use SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # Use NSX
  else if(transport == SMB_NSX)
  {
  }

  return NULL;
}

##
#
# @return
#     1     = Success
#     NULL  = Error
#
# @remark not sure what plugins use this function
##
function CloseAndDeleteFile (handle)
{
  local_var ret, transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_CloseAndDeleteFile(handle: handle);
  }

  # Use Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    if ( !isnull(handle[0]) )
      close_handle(handle[0]);

    ret = winfile_delete(handle[1]);
    if(ret == TRUE) return ret;
    else return NULL;
  }
  # Use SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # Use NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}


##
#
# @return
#   ret[...] (see direct_GetFileVersionEx())
#   NULL on error
#
##
function GetFileVersionEx(handle)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_GetFileVersionEx(handle: handle);
  }
  # Use Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    # use the same approach as a remote scan to avoid getting the wrong file version (VULN-81773)
    return direct_GetFileVersionEx(handle: handle);
  }
  # Use SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # Use NSX
  else if(transport == SMB_NSX)
  {
  }

  return NULL;
}

##
#
# @return
#   ret[0]  - Owner SID
#   ret[1]  - Group SID
#   ret[2]  - SACL
#   ret[3]  - DACL
#
#   NULL on error
##
function GetSecurityInfo (handle, level)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_GetSecurityInfo(handle: handle, level: level);
  }
  # Use Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    return winfile_securityinfo(handle: handle[0], type: level, expand: FALSE);
  }
  # Use SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # Use NSX
  else if(transport == SMB_NSX)
  {
  }

  return NULL;
}

##
#
# @return
#   4-byte file size or NULL
##
function GetFileSize (handle)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_GetFileSize(handle: handle);
  }
  # Use Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    return winfile_size(handle:handle[0]);
  }
  # Use SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # Use NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}

function GetMaxReadFileSize (handle)
{
  local_var transport, size;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    size =  session_get_server_max_size();
    if(! size)
      return NULL;
    else if (size > 110)
      return (size - 110);
    else
      return size;
  }
  # Use Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    return winfile_size(handle:handle[0]);
  }
  # Use SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # Use NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}

##
#
# @return
#   data read
#   NULL on error
#
##
function ReadFile (handle, offset, length)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_ReadFile(handle: handle, offset: offset, length: length);
  }
  # Use Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    return winfile_read(handle:handle[0], offset: offset, length:length);
  }
  # Use SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # Use NSX
  else if(transport == SMB_NSX)
  {
  }

  return NULL;

}

##
#
# @return
#   1   = Success
# NULL  = Error
##
function WriteFile (handle, offset, mode, data)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_WriteFile(handle: handle, offset: offset, mode: mode, data: data);
  }
  # Use Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    # Note: winfile_write() doesn't take 'mode' param.
    return winfile_write(handle:handle[0], offset:offset, data:data);
  }
  # Use SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # Use NSX
  else if(transport == SMB_NSX)
  {
  }

  return NULL;
}

##
# Find the first find in the directory based on the pattern
# 
# @param [pattern:regex] regex for files and directories to get
# @param [full_dir:boolean] boolean to get a full directory listing at first, rather than during the scan
#
# @return
#   ret[0] = file handle
#   ret[1] = file name
#   ret[2] = file attributes
#   ret[3] = file times [list]
#
#   NULL on error
##
function FindFirstFile (pattern, full_dir)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_FindFirstFile(pattern: pattern, full_dir: full_dir);
  }
  # Use Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    pattern = session_get_share_name() + pattern;
    return winfile_findfirst(pattern: pattern);
  }
  # Use SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # Use NSX
  else if(transport == SMB_NSX)
  {
  }

  return NULL;
}

##
#
# @return
#   ret[0] = file handle
#   ret[1] = file name
#   ret[2] = file attributes
#   ret[3] = file times [list]
#
#   NULL on error
##
function FindNextFile (handle)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_FindNextFile(handle: handle);
  }
  # Use Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    return winfile_findnext(handle: handle);
  }
  # Use SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # Use NSX
  else if(transport == SMB_NSX)
  {
  }

  return NULL;
}

#
# TODO: Wrapper functions for other SMB file APIs go here:
#





#-----------------------------------------------------------#
#   Wrapper functions for SMB registry APIs (smb_reg.inc)   #
#-----------------------------------------------------------#

##
#
# @return
#   ret[0] - registry handle
#   ret[1] - registry pipe;   NULL for SMB_LOCAL
#   ret[2] - 1 (Pipe handle); NULL for SMB_LOCAL
#   ret[3] - hkey passed to the function
#
#   NULL on error
#
##
function RegConnectRegistry (hkey)
{
  local_var ret, transport, type;

  if (isnull (hkey))
    type = HKEY_LOCAL_MACHINE;
  else
    type = hkey;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_RegConnectRegistry(hkey: hkey);
  }
  # Use Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    # Convert remote registry opnum to predefined hive key
    hkey = reg_opnum_to_hkey(hkey);

    ret[0] = hkey;
    ret[1] = NULL;  # fid; in native registry calls, no named pipe is involved.
    ret[2] = NULL;  #
    ret[3] = type;
    # if hkey was null, then ret = [NULL, NULL, NULL, NULL]
    return ret;

  }
  # Use SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # Use NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}

##
#
# @return
#   ret[0] - Key handle
#   ret[1] - FID; NULL for SMB_LOCAL
#   ret[2] - reserved
#
#   NULL on error
##
function RegOpenKey (handle, key, mode, wow)
{
  local_var hkey, ret, retry, transport;

  retry = 0;

  if (handle[3] == HKEY_LOCAL_MACHINE && get_kb_item("SMB/WoW"))
    retry = 1;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_RegOpenKey(handle: handle, key: key, mode: mode, wow: wow);
  }
  # Use Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    hkey = winreg_openkey(handle: handle[0], key: key, mode: mode);

    if (retry && isnull(hkey) && isnull(wow))
    {
      local_var pgrep_match = pgrep(pattern:"^SOFTWARE\\.*", string:key, icase:TRUE);
      # empty or null
      if (!(isnull(pgrep_match) || strlen(pgrep_match) == 0))
      {
        key = ereg_replace(pattern:"^SOFTWARE\\(.*)", string:key, replace:"SOFTWARE\\Wow6432Node\\\1", icase:TRUE);
        hkey = winreg_openkey(handle: handle[0], key: key, mode: mode);
      }
    }

    if(isnull(hkey)) return NULL;

    ret[0] = hkey;
    ret[1] = NULL; # fid
    ret[2] = 0;

    return ret;

  }
  # Use SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # Use NSX
  else if(transport == SMB_NSX)
  {
  }

  return NULL;
}

##
#
# @return
#   ret[0] - number of values
#   ret[1] - number of subkeys
#   NULL on error
##
function RegQueryInfoKey (handle)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_RegQueryInfoKey(handle: handle);
  }
  # Use Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    return winreg_queryinfokey(handle: handle[0]);
  }
  # Use SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # Use NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}

##
#
# @return
#   ret[0] - value type
#   ret[1] - value data
#   NULL on error
##
function RegQueryValue (handle, item)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_RegQueryValue(handle: handle, item: item);
  }
  # Use Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    # NULL or empty string mean 'default value' of the registry key, however
    # the agent does not accept a NULL value here.
    if (isnull(item)) item = "";
    return winreg_queryvalue(handle:handle[0], item: item);
  }
  # Use SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # Use NSX
  else if(transport == SMB_NSX)
  {
  }

  return NULL;
}

##
#
# @return
#   ret[0] - value type
#   ret[1] - value data
#   NULL on error
##
function RegEnumValue (handle, index)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_RegEnumValue(handle: handle, index: index);
  }
  # Use Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    return winreg_enumvalue(handle: handle[0], index: index);
  }
  # Use SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # Use NSX
  else if(transport == SMB_NSX)
  {
  }

  return NULL;
}

##
# @return
#   key name
#   NULL on error
##
function RegEnumKey (handle, index)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_RegEnumKey(handle: handle, index: index);
  }
  # Use Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    return winreg_enumkey(handle: handle[0], index: index);
  }
  # Use SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # Use NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}

##
# @return
#   ret[0]  - Owner SID
#   ret[1]  - Group SID
#   ret[2]  - SACL
#   ret[3]  - DACL
#   NULL on error
##
function RegGetKeySecurity (handle, type)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_RegGetKeySecurity(handle: handle, type: type);
  }
  # Use Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    return winreg_getkeysecurity(handle: handle[0], type: type, expand: FALSE);
  }
  # Use SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # Use NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}

function null_handle_check ()
{
  local_var cell;
  if (isnull(_FCT_ANON_ARGS[0])) return TRUE;
  foreach (cell in _FCT_ANON_ARGS[0])
  {
    if (!isnull(cell)) return FALSE;
  }
  return TRUE;
}

##
#
# @return
#   1 on Success
#   NULL on error
##
function RegCloseKey (handle)
{
  local_var ret, transport;
  
  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_RegCloseKey(handle: handle);
  }
  # Use Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    if (null_handle_check(handle)) return NULL;
    
    local_var env = nasl_environment();

    if(env["product"] != PRODUCT_WIN_AGENT)
    {
      ret = close_handle(handle[0]);
      if(ret == FALSE) return NULL;
        return ret;
    }

    return TRUE; 
  }
  # Use SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # Use NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}

##
#
# @return
#   ret[0] - Key handle
#   ret[1] - FID; NULL for SMB_LOCAL
#   ret[2] - reserved
#
#   NULL on error
##
function RegCreateKey (handle, key, mode)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_RegCreateKey(handle:handle, key:key, mode:mode);
  }
  # Use Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    if(defined_func("nasl_environment") && nasl_level() >= 6600)
    {
      return winreg_createkey(handle:handle[0], key:key, mode:mode);
    }
  }
  # Use SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # Use NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}

##
#
# @return
#   1 on Success
#   NULL on error
##
function RegSetValue (handle, value, type, value_data)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_RegSetValue(handle:handle, value:value, type:type, value_data:value_data);
  }
  # Use Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    if(defined_func("nasl_environment") && nasl_level() >= 6600)
    {
      return winreg_setvalue(handle:handle, item:value, type:type, value:value_data);
    }
  }
  # Use SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # Use NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}


#-----------------------------------------------------------#
#   Wrapper functions for SMB service APIs (smb_svc.inc)    #
#-----------------------------------------------------------#


##
#
# @return
#   ret[0] - handle to SCM
#   ret[1] - fid; NULL for local scan
#   ret[2] - 1;   NULL for local scan
#   NULL on error
##
function OpenSCManager (access_mode)
{
  local_var handle, ret, transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_OpenSCManager(access_mode: access_mode);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    handle = winsvc_open_manager(access_mode: access_mode);
    if(isnull(handle)) return NULL;

    ret[0] = handle;
    ret[1] = NULL;
    ret[2] = NULL;

    return ret;
  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;

}

##
# @return
#   ret[0] - service handle
#   ret[1] - FID; NULL for local scan
#   ret[2] - 0; NULL for local scan
#   NULL on error
##
function OpenService(handle, service, access_mode)
{
  local_var shandle, ret, transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_OpenService(handle: handle, service: service, access_mode: access_mode);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    shandle = winsvc_open(handle: handle[0], service: service, access_mode: access_mode);
    if(isnull(shandle)) return NULL;

    ret[0] = shandle;
    ret[1] = NULL;
    ret[2] = NULL;

    return ret;
  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;

}

##
#
# @return
#   - array of ENUM_SERVICE_STATUS
#   - Use GetService to parse each elem
#   - NULL on error
##
function EnumServicesStatus (handle, type, state)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_EnumServicesStatus(handle: handle, type: type, state: state);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    return winsvc_enum_status(handle: handle[0], type: type, state: state);
  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;

}

##
# @return
#   ret[0] - service type
#   ret[1] - current state
#   ret[2] - controls accepted
#   ret[3] - exit code
#   ret[4] - service specific exit code
#   ret[5] - check point
#   ret[6] - wait hint
#   NULL on error
##
function ControlService (handle, control)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_ControlService(handle: handle, control: control);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    return winsvc_control(handle: handle[0], control: control);
  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;

}


##
# @return
#   ret[0] - service handle created
#   ret[1] - FID; NULL for local scan
#   ret[2] -  0;  NULL for local scan
#   NULL on error
#
# @remark
#   - It appears that only wmi_malware_scan.nbin uses this function.
#
##
function CreateService (handle, service_name, display_name, desired_access, service_type, start_service, error_control, path, load_order_group, service_start_name, password)
{
  local_var shandle, ret, transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_CreateService (handle: handle,
                                 service_name: service_name,
                                 display_name: display_name,
                                 desired_access: desired_access,
                                 service_type: service_type,
                                 start_service: start_service,
                                 error_control: error_control,
                                 path: path,
                                 load_order_group: load_order_group,
                                 service_start_name: service_start_name,
                                 password: password);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    shandle = winsvc_create(handle: handle[0],
                            service_name: service_name,
                            display_name: display_name,
                            desired_access: desired_access,
                            service_type: service_type,
                            start_service: start_service,
                            error_control: error_control,
                            path: path,
                            load_order_group: load_order_group,
                            service_start_name: service_start_name,
                            password: password);
    if(isnull(shandle)) return NULL;

    ret[0] = shandle;
    ret[1] = NULL;
    ret[2] = NULL;

    return ret;
  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;

}

##
#
# @return
#   1   -  Success
# NULL on  error
##
function StartService (handle)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_StartService(handle: handle);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    return winsvc_start(handle: handle[0]);
  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;

}

##
#
# @return
#   STATUS_XXX
#   NULL on error
# @remark
#   - It appears that only wmi_malware_scan.nbin uses this function.
#
##
function DeleteService (handle)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_DeleteService(handle: handle);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    return winsvc_delete(handle: handle[0]);
  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;

}

##
#
# @return
#   1 - Success
#   NULL on error
##
function CloseServiceHandle (handle)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_CloseServiceHandle(handle: handle);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    return close_handle(handle[0]);
  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}

##
#
# @return
#   ret[0] - service type
#   ret[1] - current state
#   ret[2] - controls accepted
#   ret[3] - exit code
#   ret[4] - service specific exit code
#   ret[5] - check point
#   ret[6] - wait hint
#   NULL on error
#
##
function QueryServiceStatus (handle)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_QueryServiceStatus(handle: handle);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    return winsvc_query_status(handle:handle[0]);
  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;

}

##
#
# @return
#   displayname
#   NULL on error
##
function GetServiceDisplayName (handle, service)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_GetServiceDisplayName(handle: handle, service: service);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    return winsvc_get_displayname(handle:handle[0], service:service);
  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}


##
#
# @return
#   ret[0] - Owner SID
#   ret[1] - Group SID
#   ret[2] - SACL
#   ret[3] - DACL
#   NULL on error
#
##
function QueryServiceObjectSecurity (handle, secinfo)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_QueryServiceObjectSecurity(handle:handle, secinfo: secinfo);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    return winsvc_query_security(handle:handle[0], secinfo: secinfo);
  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}


#-----------------------------------------------------------#
#   Wrapper functions for SMB lsa APIs (smb_lsa.inc)        #
#-----------------------------------------------------------#

##
#
# @return
#   ret[0] - policy handle
#   ret[1] - fid; NULL for local scan
#   ret[2] - 1;   NULL for local scan
#   NULL on error
##
function LsaOpenPolicy (desired_access)
{
  local_var handle, ret, transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_LsaOpenPolicy(desired_access: desired_access);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    handle = winlsa_open_policy(desired_access: desired_access);
    if(isnull(handle)) return NULL;

    ret[0] = handle;
    ret[1] = NULL;
    ret[2] = NULL;

    return ret;
  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}

##
#
# @return
#   ret[0] - hostname/domain
#   ret[1] - raw sid
#   NULL on error
##
function LsaQueryInformationPolicy (handle, level)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_LsaQueryInformationPolicy(handle:handle, level:level);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    return winlsa_query_info(handle:handle[0], level:level, expand: FALSE);
  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}

##
#
# @return
#   ret[0] - user logon restrictions
#   ret[1] - unknown
#   ret[2] - service ticket lifetime (sec)
#   ret[3] - user ticket lifetime (sec)
#   ret[4] - user ticket renewal time (sec)
#   ret[5] - clock sync tolerance (sec)
#   NULL on error
##
function LsaQueryDomainInformationPolicy (handle, level)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_LsaQueryDomainInformationPolicy(handle:handle, level:level);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    return winlsa_query_domain_info(handle:handle[0], level:level);
  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}

##
#
# @return
#   array of sid_type + domain + name; sid_type = raw_dword
#   NULL on error
##
function LsaLookupSid (handle, sid_array)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_LsaLookupSid(handle:handle, sid_array: sid_array);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    return winlsa_lookup_sids(handle:handle[0], sid_array: sid_array);
  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}

##
#
# @return
#   array of sid_type + rid; sid_type = rid = raw_dword
#   NULL on error
##
function LsaLookupNames (handle, name_array)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_LsaLookupNames(handle:handle, name_array: name_array);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    return winlsa_lookup_names(handle:handle[0], name_array: name_array);
  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;

}

##
# @return
#   array of sid
#   NULL on error
#
# @remark
#   - It's unclear which plugins use this function
##
function LsaEnumerateAccountsWithUserRight (handle, right)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_LsaEnumerateAccountsWithUserRight(handle:handle, right:right);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    return winlsa_enumerate_accounts(handle:handle[0], right:right);
  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}


##
#
# @return
#   ret[0]  - Owner SID
#   ret[1]  - Group SID
#   ret[2]  - SACL
#   ret[3]  - DACL
#   NULL on error
# @remark
#   It doesn't look like there is an equivalent Windows API.
#   In local scan, we try to query the security descriptor of
#   a LSA policy object by reading a registry key. So this
#   function only supports LSA policy objects in local scan.
#   Also, caller MUST run as the SYSTEM account in order to
#   query the registry key.
#
##
function LsaQuerySecurityObject (handle, type)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_LsaQuerySecurityObject(handle:handle, type:type);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    local_var hklm, hkey, key, sd, ret;

    hklm = reg_opnum_to_hkey(HKEY_LOCAL_MACHINE);
    if(isnull(hklm))
      return NULL;

    # Open the SecDesc key, which stores the SD of the LSA policy object
    key = 'Security\\Policy\\SecDesc';
    hkey = winreg_openkey(handle: hklm, key: key, mode:MAXIMUM_ALLOWED);
    if(isnull(hkey))
      return NULL;

    # Get the default value on the key
    ret = winreg_queryvalue(handle:hkey, item: NULL);
    if(isnull(ret))
      return NULL;

    # Parse the Security Descriptor blob
    sd = parse_security_descriptor (blob: ret[1]);

    return sd;
  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}

##
#
# @return
#   1 - Success
#   NULL on error
##
function LsaClose (handle)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_LsaClose(handle:handle);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    return close_handle(handle[0]);
  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}



#-----------------------------------------------------------#
#   Wrapper functions for SMB net APIs (smb_net.inc)        #
#-----------------------------------------------------------#

##
# @return
#               [0] = platform_id (DWORD)                   #
#               [1] = hostname (STRING)                     #
#               [2] = major version(DWORD) - level 101-102  #
#               [3] = minor version(DWORD) - level 101-102  #
#               [4] = type (DWORD)         - level 101-102  #
#               [5] = comment (STRING)     - level 101-102  #
#               [6] = users (DWORD)        - level 102      #
#               [7] = disc (LONG)          - level 102      #
#               [8] = hidden (DWORD)       - level 102      #
#               [9] = announce (DWORD)     - level 102      #
#               [10] = anndelta (DWORD)    - level 102      #
#               [11] = licenses (DWORD)    - level 102      #
#               [12] = userpath (STRING)   - level 102      #
#   NULL on error
##
function NetServerGetInfo (level)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_NetServerGetInfo(level:level);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    # winnet_get_server_info(level, name)
    return winnet_get_server_info(level:level);
  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}


##
#
# @return      : array of level info                      #
#               [0] = platform_id (DWORD)                 #
#               [1] = hostname (STRING)                   #
#               [2] = domainname (STRING)                 #
#               [3] = major (DWORD)                       #
#               [4] = minor (DWORD)                       #
#               [5] = lanroot (STRING) - level 101-102    #
#               [6] = logged users (DWORD) - level 102    #
#---------------------------------------------------------#
function NetWkstaGetInfo (level)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_NetWkstaGetInfo(level:level);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    # winnet_get_wksta_info(level, name)
    return winnet_get_wksta_info(level:level);
  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}

##
#
# @return
#        -  a list of:
#            - level 0
#                - [0] cname (STRING)
#            - level 1
#                - [0] cname (STRING)
#                - [1] username (STRING)
#                - [2] num_opens (DWORD)
#                - [3] time (DWORD)
#                - [4] idle_time (DWORD)
#                - [5] user_flags (DWORD)
#            - level 2
#                - [0] cname (STRING)
#                - [1] username (STRING)
#                - [2] num_opens (DWORD)
#                - [3] time (DWORD)
#                - [4] idle_time (DWORD)
#                - [5] user_flags (DWORD)
#                - [6] cltype_name (STRING)
#            - level 10
#                - [0] cname (STRING)
#                - [1] username (STRING)
#                - [2] time (DWORD)
#                - [3] idle_time (DWORD)
#            - level 502
#                - [0] cname (STRING)
#                - [1] username (STRING)
#                - [2] num_opens (DWORD)
#                - [3] time (DWORD)
#                - [4] idle_time (DWORD)
#                - [5] user_flags (DWORD)
#                - [6] cltype_name (STRING)
#                - [7] transport (STRING)
# NULL on error
##
function NetSessionEnum (level, computer, user)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_NetSessionEnum(level:level);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    # winnet_enum_sessions(level, name, computer, user)
    return winnet_enum_sessions(level:level, computer:computer, user:user);
  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}


##
#
# @return
# NULL on error
##
function NetShareEnum (level)
{
  local_var i, j, list, keys, transport, share, ret, t;

  transport = _smb_transport();

  # SHARE_INFO_2 currently not implemented
  if(level != 0 && level != 1 && level != 502)
    return NULL;

  if (transport == SMB_DIRECT)
  {
    return direct_NetShareEnum(level:level);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    # winnet_enum_shares(level, name, expand, compat)
    if(level == 0 || level == 1)
    {
      return winnet_enum_shares(level:level, compat:TRUE);
    }
    else if (level == 502)
    {
       return winnet_enum_shares(level:level);
    }
    else return NULL;

  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}


function NetWkstaUserEnum (level)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_NetWkstaUserEnum(level:level);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    # winnet_enum_wksta_users(level, name, expand)
    return winnet_enum_wksta_users(level:level,expand:TRUE);
  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}


##
#
# @remark
#   - The Computer Browser service needs to be running
#   - nasl version uses levels 0 and 1
#   - Windows native version uses levels 100 and 101
#   - The function only accepts levels 0 and 1
##
function NetServerEnum (level)
{
  local_var transport, ret, srv;

  # Only support level 0 and 1
  if(level != 0 && level != 1)
    return NULL;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_NetServerEnum(level:level);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    # usage: winnet_enum_servers(level, domain, type, compat)

    # native version uses levels 100 and 101
    level = level + 100;

    #
    # compat mode appends an additional '\x00' to return data if
    # the 'comment' field is empty.
    # make_nested_list(
    # 'KBRDC03\0\0\0\0\0\0\0\0\0\x06\x02+\x10\x84\0\0\0\0\0\0',
    # 'RE-KRBCL3\0\0\0\0\0\0\0\x06\x01\x03\x90\x05\0\0\0\0\0\0'
    # )

    return winnet_enum_servers(level:level, type:3);

  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}

##
# Get global groups to which a user belongs
#
# @remark
#   - Seems only works if target is a DC
#
##
function NetUserGetGroups (user, resolv)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_NetUserGetGroups(user:user, resolv:resolv);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    # winnet_get_user_groups(level, name, user, expand)
    return winnet_get_user_groups(user:user);
  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}

function NetUserGetLocalGroups (user, resolv)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_NetUserGetLocalGroups(user:user, resolv:resolv);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    # winnet_get_user_local_groups(level, name, user, flags, expand)
    # Use LG_INCLUDE_INDIRECT flags, as the nasl version behaves that way
    return winnet_get_user_local_groups(user:user, flags:0x0001);
  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}

function NetLocalGroupGetMembers (group, domain)
{
  local_var transport, ret;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_NetLocalGroupGetMembers(group:group, domain:domain);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    #winnet_get_local_group_members(level, name, group, expand, compat)

    # compat mode returns the same format as the nasl version
    return winnet_get_local_group_members(group:group, compat: TRUE);

  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}

function NetGroupGetUsers (group)
{
  local_var transport;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_NetGroupGetUsers(group:group);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    # winnet_get_group_users(level, name, group, compat)
    return winnet_get_group_users(group:group, compat: TRUE);
  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}


##
#
#
# @remark
#   ret[0] = last_logon       ; 0 = never logged on
#   ret[1] = last_logoff
#   ret[2] = pwd_last_set     ; 0 = never changed password
#   ret[3] = acct_expires     ; 0 = account never expires
#   ret[4] = pwd_can_change   ; not available in native version
#   ret[5] = pwd_must_change  ; not available in native version
#   ret[6] = acct_flags       ; UF_XXX format
#
# user info for nasl version:
#  - http://msdn.microsoft.com/en-us/library/cc245622.aspx
#
# user info for native version:
#  - http://msdn.microsoft.com/en-us/library/windows/desktop/aa370654(v=vs.85).aspx
#
# difference btw nasl and native versions:
#   - pwd_last_set, pwd_can_change, and pwd_must_change not available in
#     native version
#   - acct_flags values are different
#   - timestamps in FILETIME (nasl) vs unix time (native)
#   - different encoding for special time values:
#     special FILETIMEs:
#       - 0 (seen in last_off, acct_expires)
#       - 0x7fffffffffffffff (in pwd_must_change: never expires)
#     special unix times:
#       - 0  (seen in last_off)
#       - -1 (seen in acct_expires; TIMEQ_FOREVER); converted to 0
#
##
function NetUserGetInfo (user)
{
  local_var info, transport, ret;
  local_var acct_expires, last_logon, last_logoff, pwd_last_set;
  local_var pwd_can_change, pwd_must_change, acct_flags;
  local_var high, i, low, pwd_age, tmp;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    ret = direct_NetUserGetInfo(user:user);
    if(isnull(ret)) return NULL;

    # all timestamps ini FILETIME format
    # ret[0] = last_logon;
    # ret[1] = last_logoff;       # all 0s
    # ret[2] = pwd_last_set;
    # ret[3] = acct_expires;      # all 0s means acct never expires
    # ret[4] = pwd_can_change;
    # ret[5] = pwd_must_change;   # ff ff ff ff ff ff ff 7f - pwd never expires
    # ret[6] = acct_flags;        # USER_XXX flags

    # Convert FILETIME to unixtime
    for(i = 0; i <=5; i++)
    {
      if(strlen(ret[i]) == 8)
      {
        if(ret[i] == '\x00\x00\x00\x00\x00\x00\x00\x00')
          ret[i] = 0;
        else if (ret[i] == '\xff\xff\xff\xff\xff\xff\xff\x7f')
          ret[i] = 0x7fffffff; # max positive unix time
        else
        {
          low   = get_dword(blob:ret[i], pos: 0);
          high  = get_dword(blob:ret[i], pos: 4);
          ret[i] = convert_win64_time_to_unixtime(low:low, high:high);
        }
      }
    }

    # Map USER_XXX flags to UF_XXX flags
    # http://msdn.microsoft.com/en-us/library/cc245737.aspx
    tmp = ret[6];
    acct_flags = 0;

    # USER_ACCOUNT_DISABLED
    if(tmp & 0x00000001) acct_flags = acct_flags | 0x00000002;

    # USER_HOME_DIRECTORY_REQUIRED
    if(tmp & 0x00000002) acct_flags = acct_flags | 0x00000008;

    # USER_PASSWORD_NOT_REQUIRED
    if(tmp & 0x00000004) acct_flags = acct_flags | 0x00000020;

    # USER_TEMP_DUPLICATE_ACCOUNT
    if(tmp & 0x00000008) acct_flags = acct_flags | 0x00000100;

    # USER_NORMAL_ACCOUNT
    if(tmp & 0x00000010) acct_flags = acct_flags | 0x00000200;

    # USER_MNS_LOGON_ACCOUNT
    if(tmp & 0x00000020) acct_flags = acct_flags | 0x00020000;

    # USER_INTERDOMAIN_TRUST_ACCOUNT
    if(tmp & 0x00000040) acct_flags = acct_flags | 0x00000800;

    # USER_WORKSTATION_TRUST_ACCOUNT
    if(tmp & 0x00000080) acct_flags = acct_flags | 0x00001000;

    # USER_SERVER_TRUST_ACCOUNT
    if(tmp & 0x00000100) acct_flags = acct_flags | 0x00002000;

    # USER_DONT_EXPIRE_PASSWORD
    if(tmp & 0x00000200) acct_flags = acct_flags | 0x00010000;

    # USER_ACCOUNT_AUTO_LOCKED
    if(tmp & 0x00000400) acct_flags = acct_flags | 0x00000010;

    # USER_ENCRYPTED_TEXT_PASSWORD_ALLOWED
    if(tmp & 0x00000800) acct_flags = acct_flags | 0x00000080;

    # USER_SMARTCARD_REQUIRED
    if(tmp & 0x00001000) acct_flags = acct_flags | 0x00040000;

    # USER_TRUSTED_FOR_DELEGATION
    if(tmp & 0x00002000) acct_flags = acct_flags | 0x00080000;

    # USER_NOT_DELEGATED
    if(tmp & 0x00004000) acct_flags = acct_flags | 0x00100000;

    # USER_USE_DES_KEY_ONLY
    if(tmp & 0x00008000) acct_flags = acct_flags | 0x00200000;

    # USER_DONT_REQUIRE_PREAUTH
    if(tmp & 0x00010000) acct_flags = acct_flags | 0x00400000;

    # USER_PASSWORD_EXPIRED
    if(tmp & 0x00020000) acct_flags = acct_flags | 0x00800000;

    # USER_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
    if(tmp & 0x00040000) acct_flags = acct_flags | 0x01000000;

    # USER_NO_AUTH_DATA_REQUIRED
    if(tmp & 0x00080000) acct_flags = acct_flags | 0x02000000;

    # USER_PARTIAL_SECRETS_ACCOUNT
    if(tmp & 0x00100000) acct_flags = acct_flags | 0x04000000;

    # USER_USE_AES_KEYS
    if(tmp & 0x00200000) acct_flags = acct_flags | 0x08000000;

    ret[6] = acct_flags;

    return ret;
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    # winnet_get_user_info(level, name, user, expand)
    info =  winnet_get_user_info(user:user, level:4);
    if(isnull(info)) return ret;

    last_logon    = info[13];
    last_logoff   = info[14];
    acct_expires  = info[15];  # -1 = TIMEQ_FOREVER
    acct_flags    = info[6];

    # use 0 for "account never expires"; value -1 cannot be saved to KB
    if(acct_expires == -1)
      acct_expires = 0;

    # NetUserGetInfo() doesn't return pwd_last_set
    # Compute it using password age
    pwd_age = info[2];
    pwd_last_set = NULL;
    if(! isnull(pwd_age))
    {
      if(pwd_age == 0)
        pwd_last_set = 0;
      else
        pwd_last_set = unixtime() - pwd_age;
    }

    ret[0] = last_logon;        # 0 = never logged on
    ret[1] = last_logoff;
    ret[2] = pwd_last_set;      # not in USER_INFO_X; computed from pwd_age
    ret[3] = acct_expires;
    ret[4] = NULL;              # not in USER_INFO_X
    ret[5] = NULL;              # not in USER_INFO_X
    ret[6] = acct_flags;        # UF_XXX flags

    return ret;
  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}

function NetUserGetModals (level)
{
  local_var transport, ret, t;

  transport = _smb_transport();

  if (transport == SMB_DIRECT)
  {
    return direct_NetUserGetModals(level:level);
  }
  # Local Nessus Agent
  else if(transport == SMB_LOCAL)
  {
    # winnet_get_user_modals(level, name, expand)
    if(level == 1) level = 0;
    ret = winnet_get_user_modals(level:level, expand:TRUE);
    if(isnull(ret)) return NULL;
    if(level == 0)
    {
      t[0] = ret[0]; # min pass len
      t[1] = ret[4]; # pass history len
      t[2] = NULL;   # password complexity not available in native version
      t[3] = ret[1]; # max pass age (DWORD)
      t[4] = ret[2]; # min pass age (DWORD)
      t[5] = ret[3]; # force logoff (DWORD)

      # password complexity added in 6.10
      if (max_index(ret) > 5)
      {
        t[2] = ret[5];
      }

      ret = t;
    }

    return ret;
  }
  # SMB Service
  else if(transport == SMB_SERVICE)
  {
  }
  # NSX
  else if(transport == SMB_NSX)
  {
  }
  return NULL;
}

#
# Wrappers for other SMB functions used in the plugins go here:
#

