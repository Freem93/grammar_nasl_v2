#TRUSTED 0fa60dffc9f5b58df015dd1e5bb1453d9e5d0c827b54d0100f531cbc306aac2c4443f74a3ba4d26cde8e039449e932cf834d19246a0a9e5c81247b1f3a17028939539e401443ab083e47b75f992be1a83bd9edfaf44f82f5a00ddb10d23192ba93fa1119a239350965c7ca9146ce9371b10161a61e5263ffafe3b60764ddf2350e8ef447d2ded8c7bc64a15762c8044148f7fefd54dca4ef346562fcfd8e75397c0bcf9c99c37334f9f8def269c1c3e79dad98b137d6f30cf140aefd688fb75fd4f9f853393a571be27fbebdd5ce035f500f97a305f00c5060de23deb2ca792a477f1aaa1665c7fefe93556b370c8578954aa9dfb9a3b26a9e186e8eca1d8ebca9f044c74f20f255f596d4bef21b3a5bc39879f19c9b3adef8726d3db8d45cf2755af361ebd02c66a25ef132cea1340b3fb4368828de1f13c50c545f5385281c50a78d08bd0c564b71bbdbb206ea49ced6c51de426196a868ca8df2e7dec89dfbe53bd605d69655cca547daaf68b36f0355a878dd158a545463eb802737f58dbf892fe3d2673487e187a4df73127182eff61f173d1f12a859bfc7c3ee4faaefb9ab13850b9fba2881fe1092ee213cd2af2619382b24ab8739ce41b93c04d0f3784f54ecbf99ce0d1528a7aee35487d00073d6fa967e930b9aaf98ada5f4b691da98ae52c7cbb0dbd6dfcbd8b75f546bace99cd6d3b4eb8b420065ba7f32ec05a
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
# smb_reg.inc
# Revision: 1.15
#


#==================================================================#
# Section 7. Registry API                                          #
#==================================================================#

#---------------------------------------------------------#
# Function    : RegConnectRegistry                        #
# Description : Starts registry service if not already    #
#               started.                                  #
#---------------------------------------------------------#
function startRegistrySVC()
{
  local_var handle, shandle, status, ret;

  handle = OpenSCManager(access_mode:SC_MANAGER_ALL_ACCESS);
  if(isnull(handle)) return FALSE;

  shandle = OpenService(handle:handle, service:"RemoteRegistry", access_mode:MAXIMUM_ALLOWED);
  if(isnull(shandle)) return FALSE;

  status = QueryServiceStatus(handle:shandle);
  if(isnull(status)) return FALSE;

  if(status[1] == SERVICE_STOPPED)
  {
    ret = StartService(handle:shandle);
    return ret;
  }

  if(status[1] == SERVICE_RUNNING) return TRUE;
  else return FALSE;
}

#---------------------------------------------------------#
# Function    : RegConnectRegistry                        #
# Description : Connects to the remote registry.          #
#               if not hkey connects to HKLM              #
# Return      : ret[0] : registry handle                  #
#               ret[1] : registry pipe                    #
#               ret[2] : 1 (Pipe handle)                  #
#---------------------------------------------------------#

function direct_RegConnectRegistry (hkey)
{
 local_var fid, ret, data, type, resp, rep, la, delta, vers, rr_opt;

 la = get_kb_item("SMB/remote_registry_last_access");
 vers = get_kb_item('SMB/WindowsVersion');
 rr_opt = get_preference("SMB Registry : Start the Registry Service during the scan[checkbox]:Start the registry service during the scan");
 
 # Remote registry service on Windows 8 / Server 2012 and above
 # shuts down after 10 minutes of inactivity, so we may need to
 # restart it
 if(!isnull(la) && !isnull(vers) && rr_opt == "yes")
 {
   vers = split(vers, sep:".", keep:FALSE);
   if( int(vers[0]) > 6 ||
      (int(vers[0]) == 6 && int(vers[1]) >= 2))
   {
     delta = unixtime() - la;
     if((delta / 60) >= 10)
       if(!startRegistrySVC()) return NULL;
   }
 }

 if (isnull (hkey))
   type = HKEY_LOCAL_MACHINE;
 else
   type = hkey;

 fid = bind_pipe (pipe:"winreg", uuid:"338cd001-2244-31f1-aaaa-900038001003", vers:1);
 if (isnull(fid))
 {
   # A service trigger may exist for Remote Registry when a bind call for
   # winreg is made so we'll try binding twice if the first attempt fails
   if (!get_kb_item("SMB/registry_access") && !get_kb_item("SMB/registry_not_accessible"))
   {
     sleep(2);
     fid = bind_pipe (pipe:"winreg", uuid:"338cd001-2244-31f1-aaaa-900038001003", vers:1);
     if (isnull (fid)) return NULL;
   }
   else
     return NULL;
 }

 data = raw_dword (d:0x00020000) +
        raw_word (w:0x75A0) +
	raw_word (w:0x0000) +
	raw_dword (d:0x02000000) ; # FULL_ACCESS

 data = dce_rpc_pipe_request (fid:fid, code:type, data:data);
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen (rep) != 24))
   return NULL;
 
 resp = get_dword (blob:rep, pos:20);
 if (resp != STATUS_SUCCESS)
   return NULL;
 
 replace_kb_item(name:"SMB/remote_registry_last_access", value:unixtime());

 ret = NULL;
 ret[0] = substr (rep, 0, 19);
 ret[1] = fid;
 ret[2] = 1;
 ret[3] = type;

 return ret;
}



#---------------------------------------------------------#
# Function    : _RegOpenKey                               #
# Description : Open the given key                        #
# Return      : ret[0] Key handle                         #
#               ret[1] FID                                #
#               ret[2] reserved                           #
#---------------------------------------------------------#

function _RegOpenKey (handle, key, mode)
{
  local_var data, resp, rep, name, ret, len;

  session_set_errorcode(code:STATUS_SUCCESS);

  name = cstring (string:key);
  len = strlen(name);

  data = handle[0]                                         + # Handle
  class_parameter (ref_id:0x00020000, name:key, size:TRUE) + # Key Name
  raw_dword (d:0)                                          + # Unknown
  raw_dword (d:mode);                                        # Mask

  data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_OPENKEY, data:data);
  if (!data)
    return NULL;

  # response structure :
  # Policy handle (20 bytes)
  # return code (dword)

  rep = dce_rpc_parse_response (fid:handle[1], data:data);
  if (!rep || (strlen (rep) != 24))
    return NULL;

  resp = get_dword (blob:rep, pos:20);
  if (resp != STATUS_SUCCESS)
  {
    session_set_errorcode(code:resp);
    return NULL;
  }

  ret = NULL;
  ret[0] = substr (rep, 0, 19);
  ret[1] = handle[1];
  ret[2] = 0;

  return ret;
}


#---------------------------------------------------------#
# Function    : RegOpenKey                               #
# Description : Open the given key                        #
# Return      : ret[0] Key handle                         #
#               ret[1] FID                                #
#               ret[2] reserved                           #
#---------------------------------------------------------#

function direct_RegOpenKey (handle, key, mode, wow)
{
  local_var retry, ret;

  retry = 0;

  if (handle[3] == HKEY_LOCAL_MACHINE && get_kb_item("SMB/WoW"))
    retry = 1;

  ret = _RegOpenKey(handle:handle, key:key, mode:mode);

  if (retry && isnull(ret) && isnull(wow))
  {
    local_var pgrep_match = pgrep(pattern:"^SOFTWARE\\.*", string:key, icase:TRUE);
    # not empty or null
    if (!(isnull(pgrep_match) || strlen(pgrep_match) == 0))
    {
      key = ereg_replace(pattern:"^SOFTWARE\\(.*)", string:key, replace:"SOFTWARE\\Wow6432Node\\\1", icase:TRUE);
      ret = _RegOpenKey(handle:handle, key:key, mode:mode);
    }
  }

  return ret;
}


#---------------------------------------------------------#
# Function    : RegQueryInfoKey                           #
# Description : Retrieve key information                  #
# Return      : returns number of values and sub keys     #
#               ret[0] values                             #
#               ret[1] subkeys                            # 
#---------------------------------------------------------#

function direct_RegQueryInfoKey (handle)
{
 local_var data, resp, rep, ret;

 data = handle[0]          +  # Handle
        raw_word (w:0)     +  # Length
	      raw_word (w:0)     +  # Size
	      raw_dword (d:0);      # NULL 
 
 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_QUERYINFOKEY, data:data);
 if (!data)
   return NULL;

 # response structure :
 # Class (bad parsed here)
 # num subkeys
 # max subkey len
 # reserved
 # num value
 # max value len
 # max valbuf size
 # secdesc len
 # mod time
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) != 48))
   return NULL;
 
 resp = get_dword (blob:rep, pos:44);
 if (resp != STATUS_SUCCESS)
   return NULL;

 ret = NULL;
 ret[0] = get_dword (blob:rep, pos:20);
 ret[1] = get_dword (blob:rep, pos:8);

 return ret;
}



#---------------------------------------------------------#
# Function    : RegQueryValue                             #
# Description : Retrieve value about key's item           #
# Return      : returns item value                        #
#               ret[0] type                               #
#               ret[1] value                              #
#---------------------------------------------------------#

function direct_RegQueryValue (handle, item)
{
  local_var data, resp, rep, ret, name, len;
  local_var ref_id, key_type, key_data, code, max_count, offset, actual_count, pos;

  session_set_errorcode(code:STATUS_SUCCESS);

  if (strlen(item) > 0)
    name = class_parameter (ref_id:0x00020000, name:item, size:TRUE);
  else
    name = raw_word(w:2) + raw_word (w:0) + raw_dword (d:0);  # (default) value does not work with RegQueryValueEx

  data = handle[0] +                                         # Handle
         name +                                              # Class
         buffer_parameter (ref_id:0x00020004, size:0) +      # Reserved
         buffer_parameter (ref_id:0x00020008, size:0xFFFF) + # Offered
         raw_dword (d:0) +                                   # unknown
         raw_dword (d:0) +                                   # unknown
         buffer_parameter (ref_id:0x0002000C, size:0xFFFF) + # Offered
         buffer_parameter (ref_id:0x00020010, size:0);       # Returned

  data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_QUERYVALUE, data:data);
  if (!data)
    return NULL;

  rep = dce_rpc_parse_response (fid:handle[1], data:data);
  if (!rep || (strlen (rep) < 16))
    return NULL;

  # Return code
  code = get_dword (blob:rep, pos:strlen(rep)-4);
  if (code != STATUS_SUCCESS)
  {
    session_set_errorcode(code:code);
    return NULL;
  }

  # Key Type
  ref_id = get_dword (blob:rep, pos:0);
  key_type = get_dword (blob:rep, pos:4);

  # Key Data
  ref_id = get_dword (blob:rep, pos:8);
  max_count = get_dword (blob:rep, pos:12);
  offset = get_dword (blob:rep, pos:16);
  actual_count = get_dword (blob:rep, pos:20);
  if (strlen(rep) < 24+actual_count+20)
    return NULL;

  pos = 0;

  if ((key_type == REG_SZ) || (key_type == REG_EXPAND_SZ) || (key_type == REG_MULTI_SZ))
  {
    key_data = get_string2 (blob:rep, pos:24, len:actual_count, _type:UNICODE_STRING);
    while ((actual_count % 4) != 0)
    {
      actual_count++;
      pos++;
    }
  }
  else if (key_type == REG_DWORD)
  {
    key_data = get_dword (blob:rep, pos:24);
  }
    else if (key_type == REG_QWORD)
  {
    # nb: these are 64-bit values; we don't support this type yet.
    return NULL;
  }
  else
    key_data = substr (rep, 24, 24+actual_count-1);


  ret = NULL;
  ret[0] = key_type;
  ret[1] = key_data;  # we must convert type here

  return ret;
}



#---------------------------------------------------------#
# Function    : RegEnumValue                              #
# Description : Retrieve index type and value             #
# Return      : returns key value                         #
#               ret[0] type                               #
#               ret[1] value                              #
#---------------------------------------------------------#

function direct_RegEnumValue (handle, index)
{
 local_var data, resp, rep, ret, name, len, pos;
 local_var unknown1, unknown2, ref_id, key_type, key_name, reserved, val, code, len_2;

 data = handle[0]  +  # Handle

	raw_dword (d:index)          +  # num
	raw_dword (d:0x20000000)     +  # unknown

	raw_dword (d:0x20000)        +  # Referent ID
	raw_dword (d:0x1000)         +  # unknown
	raw_dword (d:0)              +  # unknown
	raw_dword (d:0)              +  # unknown

	raw_dword (d:0x20004)        +  # Referent ID
	raw_dword (d:0)              +  # Pointer
	raw_dword (d:0)              +  # reserved

        buffer_parameter (ref_id:0x00020008, size:0) +

        buffer_parameter (ref_id:0x0002000C, size:0);

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_ENUMVALUE, data:data);
 if (!data)
   return NULL;

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 24))
   return NULL;
 
 # Key name
 len = get_word (blob:rep, pos:0);
 unknown1 = get_word (blob:rep, pos:2); # 0x200 ?
 ref_id = get_dword (blob:rep, pos:4);
 unknown2 = get_dword (blob:rep, pos:8);
 reserved = get_dword (blob:rep, pos:12);
 len_2 = get_dword (blob:rep, pos:16);
 
 pos = 20 + len;
 # Extra 2 bytes pad if len_2 odd
 if ((len_2 % 2) == 1)
   pos += 2; 

 if (strlen (rep) < pos+32)
   return NULL;

 key_name = get_string (blob:rep, pos:20);
 
 # Key type
 ref_id = get_dword (blob:rep, pos:pos);
 key_type = get_dword (blob:rep, pos:pos+4);
 reserved = get_dword (blob:rep, pos:pos+8);

 # Offered
 ref_id = get_dword (blob:rep, pos:pos+12);
 val = get_dword (blob:rep, pos:pos+16);

 # Returned
 ref_id = get_dword (blob:rep, pos:pos+20);
 val = get_dword (blob:rep, pos:pos+24);

 # Return code
 code = get_dword (blob:rep, pos:pos+28);
 if (code != STATUS_SUCCESS)
   return NULL;
 
 ret = NULL;
 ret[0] = key_type;
 ret[1] = key_name;

 return ret;
}


#---------------------------------------------------------#
# Function    : RegEnumKey                                #
# Description : Returns key's index name                  #
#---------------------------------------------------------#

function direct_RegEnumKey (handle, index)
{
 local_var data, resp, rep, ret, name, len, len_2;
 local_var unknown1, unknown2, ref_id, key_type, key_name, reserved, code, pos;

 data = handle[0]  +  # Handle

	raw_dword (d:index)          +  # num
	raw_dword (d:0x20000000)     +  # unknown

	raw_dword (d:0x20000)        +  # Referent ID
	raw_dword (d:0x1000)         +  # unknown
	raw_dword (d:0)              +  # unknown
	raw_dword (d:0)              +  # unknown

	raw_dword (d:0x20004)        +  # Referent ID
	raw_dword (d:0)              +  # Pointer
	raw_dword (d:0)              +  # reserved
	raw_dword (d:0) ;               # reserved

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_ENUMKEY, data:data);
 if (!data)
   return NULL;

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 24))
   return NULL;
 
 # Key name
 len = get_word (blob:rep, pos:0);
 unknown1 = get_word (blob:rep, pos:2); # 0x200 ?
 ref_id = get_dword (blob:rep, pos:4);
 unknown2 = get_dword (blob:rep, pos:8);
 reserved = get_dword (blob:rep, pos:12);
 len_2 = get_dword (blob:rep, pos:16);
 
 pos = 20 + len;
 # Extra 2 bytes pad if len_2 odd
 if ((len_2 % 2) == 1)
   pos += 2; 

 if (strlen (rep) < pos+20)
   return NULL;

 key_name = get_string (blob:rep, pos:20);
 
 #Returned 
 ref_id = get_dword (blob:rep, pos:pos);
 reserved = get_dword (blob:rep, pos:pos+4);
 reserved = get_dword (blob:rep, pos:pos+8);
 reserved = get_dword (blob:rep, pos:pos+12);

 # Return code
 code = get_dword (blob:rep, pos:pos+16);
 if (code != STATUS_SUCCESS)
   return NULL;
 
 ret = key_name;

 return ret;
}



#---------------------------------------------------------#
# Function    : RegCloseKey                               #
# Description : Close key handle                          #
# Return      : 1 on success                              #
#---------------------------------------------------------#

function direct_RegCloseKey (handle)
{
 local_var data, rep, code, ret;

 code = NULL;
 
 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_CLOSEKEY, data:handle[0]);
 if (data)
 {
  rep = dce_rpc_parse_response (fid:handle[1], data:data);
  if (rep && (strlen (rep) == 24))
  { 
   # NULL handle (useless) + code
   # Return code
   code = get_dword (blob:rep, pos:20);
  }
 }

 if (handle[2] == 1)
   ret = smb_close (fid:handle[1]);
 
 if (isnull (code) || (code != STATUS_SUCCESS) || (ret != 1))
   return NULL;
 
 return 1;
}



#---------------------------------------------------------#
# Function    : RegGetKeySecurity                         #
# Description : Return Key Security Descriptor            #
# Type        : xxx_SECURITY_INFORMATION                  #
#               xxx = DACL, SACL, GROUP, OWNER            #
#               | to use multiple level                   #
#---------------------------------------------------------#

function direct_RegGetKeySecurity (handle, type)
{
 local_var data, rep, ret, len, code, ref_id, offset, size, unknown, sec_desc, size2;
 local_var length, max_count, actual_count;

 data = handle[0] +
        raw_dword (d:type) +
	raw_dword (d:0)    + # Referent ID;
	raw_dword (d:0)    + # Length
	raw_dword (d:0)    + # Offset
	raw_dword (d:0xFFFFFFFF) ;    # Size
	
 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_GETKEYSECURITY, data:data);
 if (!data)
   return NULL;

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 16))
   return NULL;
 
 # Referent ID
 # length
 # offset
 # return code

 ref_id = get_dword (blob:rep, pos:0);
 len = get_dword (blob:rep, pos:4);
 offset = get_dword (blob:rep, pos:8);
 code = get_dword (blob:rep, pos:strlen(rep)-4);
 if (code != ERROR_INSUFFICIENT_BUFFER)
   return NULL;
 
 # Now we do the same request but with the length of our allowed buffer (useless in fact with nasl)

 data = handle[0]                +
        raw_dword (d:type)       +
	raw_dword (d:0x20000)    + # Referent ID;
	raw_dword (d:len)        + # Length
	raw_dword (d:0)          + # Offset
	raw_dword (d:len)        + # Size
	raw_dword (d:0)          + # reserved
	raw_dword (d:0) ;          # reserved
	
 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_GETKEYSECURITY, data:data);
 if (!data)
   return NULL;

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 24))
   return NULL;
 
 # Referent ID
 # length
 # offset
 # return code

 ref_id = get_dword (blob:rep, pos:0);
 len = get_dword (blob:rep, pos:4);
 size = get_dword (blob:rep, pos:8);
 actual_count = get_dword (blob:rep, pos:12);
 offset = get_dword (blob:rep, pos:16);
 max_count = get_dword (blob:rep, pos:20);

 if (strlen (rep) < 24+len+4)
   return NULL;

 sec_desc = substr (rep, 24, 24+len-1);
 sec_desc = parse_security_descriptor (blob:sec_desc);

 code = get_dword (blob:rep, pos:24+len);
 if (code != STATUS_SUCCESS)
   return NULL;
 
 return sec_desc;
}


#---------------------------------------------------------#
# Function    : RegCreateKey                              #
# Description : Create key / subkeys                      #
# Return      : ret[0] Key handle                         #
#               ret[1] FID                                #
#               ret[2] reserved                           #
#                                                         #
#               NULL if error                             #
#---------------------------------------------------------#

function direct_RegCreateKey (handle, key, mode)
{
  local_var data, resp, rep, ret, name, len, code;

  session_set_errorcode(code:STATUS_SUCCESS);

  name = class_parameter (ref_id:0x00020000, name:key, size:TRUE);

  data = handle[0] +           # Handle
         name +                # Subkey
         raw_dword (d:0) +     # Class
         raw_dword (d:0) +     # Options
         raw_dword (d:0) +     # unknown
         raw_dword (d:mode) +  # Mask
         raw_dword (d:0) +     # Secdesc
         buffer_parameter (ref_id:0x00020004, size:0); # Action taken

  data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_CREATEKEY, data:data);
  if (!data)
    return NULL;

  # Handle is returned
  rep = dce_rpc_parse_response (fid:handle[1], data:data);
  if (!rep || (strlen (rep) < 24))
    return NULL;

  # Return code
  code = get_dword (blob:rep, pos:strlen(rep)-4);
  if (code != STATUS_SUCCESS)
  {
    session_set_errorcode(code:code);
    return NULL;
  }

  ret = NULL;
  ret[0] = substr (rep, 0, 19);
  ret[1] = handle[1];
  ret[2] = 0;

  return ret;
}


#---------------------------------------------------------#
# Function    : RegSetValue                               #
# Description : Create value and its associated data      #
# Return      : TRUE if successful                        #
#               NULL if an error occurred                 #
#---------------------------------------------------------#

function direct_RegSetValue (handle, value, type, value_data)
{
  local_var data, rep, value_encoded, value_data_encoded, value_data_len, code;

  session_set_errorcode(code:STATUS_SUCCESS);
  
  value_encoded = class_parameter (ref_id:0x00020000, name:value, size:TRUE);
  value_data_encoded = cstring(string:value_data);
  value_data_len = strlen(value_data_encoded);

  data = handle[0] +                    # Handle
         value_encoded +                # Value
         raw_dword (d:type) +           # Type
         raw_dword (d:value_data_len) + # Max Count 
         value_data_encoded +           # Data
         raw_byte (b:0) +               # unknown
         raw_byte (b:0) +               # unknown
         raw_dword (d:value_data_len);  # Size

  data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_SETVALUE, data:data);
  if (!data)
    return NULL;

  rep = dce_rpc_parse_response (fid:handle[1], data:data);
  if (!rep)
    return NULL;

  # Return code
  code = get_dword (blob:rep, pos:strlen(rep)-4);
  if (code != STATUS_SUCCESS)
  {
    session_set_errorcode(code:code);
    return NULL;
  }

  return TRUE;
}


##
# hive_int2str
#
# converts the integer representation of a registry hive to its string
# equivalent. e.g. hive_int2str(HKEY_LOCAL_MACHINE) returns the string
# 'HKEY_LOCAL_MACHINE'
#
# @param  int  int constant representing the desired hive
# @return the string name of the registry hive if 'int' is valid, or
#         NULL otherwise
##
function hive_int2str()
{
  local_var int, str;
  int = _FCT_ANON_ARGS[0];

  if (int == HKEY_LOCAL_MACHINE)
    str = 'HKEY_LOCAL_MACHINE';
  else if (int == HKEY_CURRENT_USER)
    str = 'HKEY_CURRENT_USER';
  else if (int == HKEY_USERS)
    str = 'HKEY_USERS';
  else if (int == HKEY_CLASS_ROOT)
    str = 'HKEY_CLASS_ROOT';
  else
    str = NULL;

  return str;
}

function reg_opnum_to_hkey()
{
  local_var opnum;

  opnum = _FCT_ANON_ARGS[0];

  if (opnum == HKEY_CLASS_ROOT)         # opnum 0
    return 0x80000000; 
  else if (opnum == HKEY_CURRENT_USER)  # opnum 1
    return 0x80000001; 
  if(opnum == HKEY_LOCAL_MACHINE)       # opnum 2
    return 0x80000002;                  
  else if (opnum == 3)                  # OpenPerformanceData
    return 0x80000004;
  else if (opnum == HKEY_USERS)         # opnum 4
    return 0x80000003;                  
  else if (opnum == 27)                 # OpenCurrentConfig
    return 0x80000005;
  else if (opnum == 32)                 # OpenPerformanceText
    return 0x80000050;
  else if (opnum == 33)                 # OpenPerformanceNlsText
    return 0x80000060;
  else return NULL;

}
