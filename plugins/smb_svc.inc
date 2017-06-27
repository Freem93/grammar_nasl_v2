#TRUSTED 89bac7aa47bff7318973406b640afefde4b84a5788e75c747339c496fcb8bb87a28b69abb2045fd8232fc9f58cc923bc06498e2a70f75ef9a6867c4f1161a97dcede83f2a4cdbfe92df9424883c0d6feef4cfea0bf3b6bfd3f041d0b774668f956934feb08e9416467cff30e9ba958424e65aa68be36f960a735ac57b4a2632ba2eba8d15b633c61da73d5dbf06283189eb67f6e273620ca13b75247215f5b37257327e8eefa632b36f4b4f403e6451440173a3253991f2cf5e61c9248b9ea99adda4c6f5d83aefa0993b052b416cc6869ea0a1f737b5f587f8feccd4d557cb6b7d62d316a0ca645a77b88c7a127e227c249f859a6fc8783c615be8479bc090b926d786c07a5f6aa5730908f65648f35c38ace4151bbdf51c291bfee674bd7f4b65611b30965b4ff0d5574d0c840d8f78c9a33b20022fab3c8df30966237cf674472db5bfea7210101d256459d1e13c7d1bda43e24d9f2612cf13111b86ee49f772d42da7129874bce1d09d8d4d9bd6cd3c6ee6aa32189c43ef005f4085d3861551272e1e32f5658d79ef11e047f56fab2d01ae994810c8798a381fbe27d7180ed51e85e9a480dbc521733d352f276780def96548c07ba07b4e3dde5ea73884b2c03584865a6ba5ef1d5e98a00b65102a75d0ccc346d78ecc3a7eb7a4db6a2e33ba46401c942f1f892023d2ddc1a66d8897f921688ac69c3bc188c9f8d56d495
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
# smb_svc.inc
# Revision: 1.7
#


#==================================================================#
# Section 9. Service API                                           #
#==================================================================#


#---------------------------------------------------------#
# Function    : OpenSCManager                             #
# Description : Open Service Manager                      #
#---------------------------------------------------------#

function direct_OpenSCManager (access_mode)
{
 local_var fid, ret, data, type, resp, rep, name, opnum;

 fid = bind_pipe (pipe:"svcctl", uuid:"367abb81-9844-35f1-ad32-98f038001003", vers:2);
 if (isnull (fid))
   return NULL;

 if (session_is_unicode() == 1)
   opnum = OPNUM_OPENSCMANAGERW;
 else
   opnum = OPNUM_OPENSCMANAGERA;
 
 data = raw_dword (d:0x0020000)                       + # ref_id
        class_name (name:"\\"+session_get_hostname()) +
        raw_dword (d:0)                               + # NULL database pointer 
        raw_dword (d:access_mode) ;                     # Desired Access

 data = dce_rpc_pipe_request (fid:fid, code:opnum, data:data);
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

 ret = NULL;
 ret[0] = substr (rep, 0, 19);
 ret[1] = fid;
 ret[2] = 1;

 return ret;
}



#---------------------------------------------------------#
# Function    : OpenService                               #
# Description : Open the given service                    #
# Return      : ret[0] service handle                     #
#               ret[1] FID                                #
#               ret[2] reserved                           #
#---------------------------------------------------------#

function direct_OpenService (handle, service, access_mode)
{
 local_var data, resp, rep, tmp, ret, len, opnum;

 if (session_is_unicode() == 1)
   opnum = OPNUM_OPENSERVICEW;
 else
   opnum = OPNUM_OPENSERVICEA;

 data = handle[0]                     +  # Handle
        class_name(name:service)      +  # service name  
        raw_dword (d:access_mode) ;
        
 data = dce_rpc_pipe_request (fid:handle[1], code:opnum, data:data);
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
   return NULL;

 ret = NULL;
 ret[0] = substr (rep, 0, 19);
 ret[1] = handle[1];
 ret[2] = 0;
 
 return ret;
}


#---------------------------------------------------------#
# Function    : GetService                                #
# Description : Return service information                #
# Return      :                                           #
#                                                         #
#  BYTE  Name[];                                          #
#  BYTE  Description[];                                   #
#  DWORD dwServiceType;                                   #
#  DWORD dwCurrentState;                                  #
#  DWORD dwControlsAccepted;                              #
#  DWORD dwWin32ExitCode;                                 #
#  DWORD dwServiceSpecificExitCode;                       #
#  DWORD dwCheckPoint;                                    #
#  DWORD dwWaitHint;                                      #
#---------------------------------------------------------#

function GetService (service)
{
 local_var tab, ret, pos, name, desc, s;

 ret = NULL;

 pos = 0;
 name = desc = NULL;
 
 while (ord(service[pos]) != 0x01)
 {
  name += service[pos];
  pos++;
 }

 pos++;

 while (ord(service[pos]) != 0x01)
 {
  desc += service[pos];
  pos++;
 }

 pos++;

 ret[0] = name;
 ret[1] = desc;
 ret[2] = get_dword (blob:service, pos:pos);
 ret[3] = get_dword (blob:service, pos:pos+4);
 ret[4] = get_dword (blob:service, pos:pos+8);
 ret[5] = get_dword (blob:service, pos:pos+12);
 ret[6] = get_dword (blob:service, pos:pos+16);
 ret[7] = get_dword (blob:service, pos:pos+20);
 ret[8] = get_dword (blob:service, pos:pos+24);
 
 return ret;
}


#---------------------------------------------------------#
# Function    : EnumServicesStatus                        #
# Description : Enumerate services                        #
# Return      : array of ENUM_SERVICE_STATUS              #
#               Use GetService to parse each elem         #
#---------------------------------------------------------#

function direct_EnumServicesStatus (handle, type, state)
{
  local_var data, resp, rep, ret, length, pos, name_pt, 
            desc_pt, service_status, opnum, i, array, num;

  if (session_is_unicode() == 1)
    opnum = OPNUM_ENUMSERVICEW;
  else
    opnum = OPNUM_ENUMSERVICEA;

  # We must first send a 0 byte array else if we use a 0xFFFF length array
  # Windows will return 0xFFFF bytes instead of the real buffer size ...

  data = handle[0]                +  # Handle
         raw_dword (d:type)       +  # service type
         raw_dword (d:state)      +  # service state
         raw_dword (d:0)          +  # buffer size
         raw_dword (d:0x00020000) +  # pointer
         raw_dword (d:0);            # NULL pointer

  data = dce_rpc_pipe_request(fid:handle[1], code:opnum, data:data);
  if (!data)
    return NULL;

  rep = dce_rpc_parse_response(fid:handle[1], data:data);
  if (!rep || (strlen(rep) < 10))
    return NULL;

  resp = get_dword(blob:rep, pos:strlen(rep)-4);
  if (resp != ERROR_MORE_DATA)
    return NULL;

  length = get_dword(blob:rep, pos:4);

  data = handle[0]               +  # Handle
         raw_dword(d:type)       +  # service type
         raw_dword(d:state)      +  # service state
         raw_dword(d:length)     +  # buffer size
         raw_dword(d:0x00020000) +  # pointer
         raw_dword(d:0);            # NULL pointer

  data = dce_rpc_pipe_request(fid:handle[1], code:opnum, data:data);
  if (!data)
    return NULL;

  rep = dce_rpc_parse_response(fid:handle[1], data:data);
  if (!rep || (strlen(rep) < 4))
    return NULL;

  resp = get_dword(blob:rep, pos:strlen(rep)-4);
  if (resp != STATUS_SUCCESS)
    return NULL;

  length = get_dword(blob:rep, pos:0);
  pos = 4 + length + length%4; 

  if (strlen(rep) != pos+20)
    return NULL;

  array = substr(rep, 4, length+4-1);

  # unknown1 = get_dword(blob:rep, pos:pos);

  num = get_dword(blob:rep, pos:pos+4);

  # ref_id = get_dword(blob:rep, pos:pos+8);
  # pointer = get_dword(blob:rep, pos:pos+12);

  pos = 0;
  ret = NULL;

  # for each service
  for (i=0; i<num; i++)
  {
    name_pt = get_dword(blob:array, pos:pos);
    desc_pt = get_dword(blob:array, pos:pos+4);

    # SERVICE_STATUS structure : length = 28
    service_status = substr(array, pos+8, pos+35);

    pos += 36;

    ret[i] = get_string(blob:array, pos:name_pt) + raw_byte(b:0x01) +
             get_string(blob:array, pos:desc_pt) + raw_byte(b:0x01) +
             service_status;
  }

  return ret;
}


#---------------------------------------------------------#
# Function    : ControlService                            #
# Description : Send control message to service           #
#---------------------------------------------------------#

function direct_ControlService (handle, control)
{
 local_var data, resp, rep, ret;

 data = handle[0]                     +  # Handle
        raw_dword (d:control) ;          # Info level
        
 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_SERVICECONTROL, data:data);
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 10))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;

 ret = NULL;
 ret[0] = get_dword (blob:rep, pos:0);    # service type
 ret[1] = get_dword (blob:rep, pos:4);    # current state 
 ret[2] = get_dword (blob:rep, pos:8);    # controls accepted
 ret[3] = get_dword (blob:rep, pos:12);   # exit code
 ret[4] = get_dword (blob:rep, pos:16);   # service specific exit code
 ret[5] = get_dword (blob:rep, pos:20);   # check point
 ret[6] = get_dword (blob:rep, pos:24);   # wait hint

 return ret;
}


#---------------------------------------------------------#
# Function    : CreateService                             #
# Description : Add a new service                         #
#---------------------------------------------------------#

function direct_CreateService (handle, service_name, display_name, desired_access, service_type, start_service, error_control, path, load_order_group, service_start_name, password)
{
 local_var data, resp, rep, ret, unknown, opnum, name;

 if (session_is_unicode() == 1)
   opnum = OPNUM_CREATESERVICEW;
 else
   opnum = OPNUM_CREATESERVICEA;

 data = handle[0]                            +  # Handle
        class_name (name:service_name)       +  # Service Name
        raw_dword (d:0x00020000)             +  # Ref ID
        class_name (name:display_name)       +  # Display Name
        raw_dword (d:desired_access)         +  # Desired Access
        raw_dword (d:service_type)           +  # Service Type
        raw_dword (d:start_service)          +  # StartService
        raw_dword (d:error_control)          +  # ErrorControl
        class_name (name:path)               +  # Path
        class_name (name:load_order_group)   +  # LoadOrderGroup
        raw_dword (d:0)                      +  # pointer to tagid
        raw_dword (d:0)                      +  # array of string
        class_name (name:service_start_name) +  # Service Start Name
        class_name (name:password)           +  # Password (depend of Service Start Name)
        raw_dword (d:0)                      +  # unknown
        raw_dword (d:0) ;                       # unknown
       
 data = dce_rpc_pipe_request (fid:handle[1], code:opnum, data:data);
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 28))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;

 unknown = get_dword (blob:rep, pos:0);

 ret = NULL;
 ret[0] = substr (rep, 4, 23);
 ret[1] = handle[1];
 ret[2] = 0;
 
 return ret;
}


#---------------------------------------------------------#
# Function    : StartService                              #
# Description : Start a service                           #
#---------------------------------------------------------#

function direct_StartService (handle)
{
 local_var data, resp, rep, ret, unknown, opnum, name;

 if (session_is_unicode() == 1)
   opnum = OPNUM_STARTSERVICEW;
 else
   opnum = OPNUM_STARTSERVICEA;

 data = handle[0] + #handle
        raw_dword (d:0) + # NULL pointer
        raw_dword (d:0) ; # NULL pointer
       
 data = dce_rpc_pipe_request (fid:handle[1], code:opnum, data:data);
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) != 4))
   return NULL;
 
 resp = get_dword (blob:rep, pos:0);
 if (resp != STATUS_SUCCESS)
   return NULL;

 return 1;
}


#---------------------------------------------------------#
# Function    : DeleteService                             #
# Description : Delete a service                          #
#---------------------------------------------------------#

function direct_DeleteService (handle)
{
 local_var data, resp, rep;

 data = handle[0] ; # Handle
       
 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_DELETESERVICE, data:data);
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 4))
   return NULL;
 
 resp = get_dword (blob:rep, pos:0);
 if (resp != STATUS_SUCCESS)
   return NULL;
 
 return resp;
}



#---------------------------------------------------------#
# Function    : CloseServiceHandle                        #
# Description : Close service handle                      #
# Return      : 1 on success                              #
#---------------------------------------------------------#

function direct_CloseServiceHandle (handle)
{
 local_var data, rep, code, ret;

 code = NULL;
 
 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_CLOSESERVICE, data:handle[0]);
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
# Function    : QueryServiceStatus                        #
# Description : Query service status                      #
#---------------------------------------------------------#

function direct_QueryServiceStatus (handle)
{
 local_var data, resp, rep, ret;

 data = handle[0] ;  # Handle
        
 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_QUERYSERVICE, data:data);
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 10))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;

 ret = NULL;
 ret[0] = get_dword (blob:rep, pos:0);    # service type
 ret[1] = get_dword (blob:rep, pos:4);    # current state 
 ret[2] = get_dword (blob:rep, pos:8);    # controls accepted
 ret[3] = get_dword (blob:rep, pos:12);   # exit code
 ret[4] = get_dword (blob:rep, pos:16);   # service specific exit code
 ret[5] = get_dword (blob:rep, pos:20);   # check point
 ret[6] = get_dword (blob:rep, pos:24);   # wait hint

 return ret;
}



#---------------------------------------------------------#
# Function    : GetServiceDisplayName                     #
# Description : Get Service Display Name                  #
#---------------------------------------------------------#

function direct_GetServiceDisplayName (handle, service)
{
 local_var data, resp, rep, len, max_count, offset, actual_count, opcode;

 if (session_is_unicode ())
   opcode = OPNUM_SERVICEDISPLAYNAMEW;
 else
   opcode = OPNUM_SERVICEDISPLAYNAMEA;

  #
  # [MS-SCMR]
  # 
  # DWORD RGetServiceDisplayNameW(
  # [in] SC_RPC_HANDLE hSCManager,
  # [in, string, range(0, SC_MAX_NAME_LENGTH)]
  # wchar_t* lpServiceName,
  # [out, string, range(1, 4*1024+1), size_is(*
  # lpcchBuffer +1)]
  # wchar_t* lpDisplayName,
  # [in, out] DWORD* lpcchBuffer
  # );
  #
 data = handle[0] +  # Handle
        class_name (name:service) +
        raw_dword (d: 4 * 1024);
        
 data = dce_rpc_pipe_request (fid:handle[1], code:opcode, data:data);
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 10))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;


 # name array
 max_count = get_dword (blob:rep, pos:0);
 offset = get_dword (blob:rep, pos:4);
 actual_count = get_dword (blob:rep, pos:8);

 if (session_is_unicode ())
   len = actual_count * 2;
 else
   len = actual_count;

 if (strlen(rep) < 12 + len)
   return NULL;

 return get_string2 (blob:rep, pos:12, len:len);
}


#---------------------------------------------------------#
# Function    : QueryServiceObjectSecurity                #
# Description : Query service security                    #
#---------------------------------------------------------#

function direct_QueryServiceObjectSecurity (handle, secinfo)
{
 local_var data, resp, rep, ret, size, buffer_size;

 data = handle[0]        +  # Handle
        raw_dword (d:secinfo)  +  # level (DACL|SACL)
        raw_dword (d:0);    # buffer size
        
 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_QUERYSERVICESECURITY, data:data);
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 12))
   return NULL;
 
 # buffer too small
 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != 0x7A)
   return NULL;

 buffer_size = get_dword (blob:rep, pos:4);

 data = handle[0]        +  # Handle
        raw_dword (d:secinfo)  +  # level (DACL|SACL)
        raw_dword (d:buffer_size);    # buffer size
        
 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_QUERYSERVICESECURITY, data:data);
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 12))
   return NULL;

 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;

 size = get_dword (blob:rep, pos:0);
 if (strlen(rep) < (size+8))
   return NULL;

 return parse_security_descriptor (blob:substr(rep, 4, strlen(rep)-5));
}



