#TRUSTED 86e8a7705a660314c15bfadfd9558466631c3c2a904035ca80d72fad82da462de2231fd51e2a0f2b23902da28f930a3dff8d0f979264905af996218e38c71b3ad1e5f60d05f3c7a5945947c10ba7e6a9529b51561027c0e660fe5cf803d48e445fa6af082f837afa92bea369535b1c11993f47320a8305c88820aaf8e8ebe152503586d8592a8a4b3fdcdc6cddda56dc50f4d80a76aa4aa52604a204fe405f67032702891e991ca0a67178faa06593b4504e5be26379c4c0548dd4a73f0fd730913870d9928b2c7bff1a90eaead14d9005df4223e1973d89487773c80f247b2975b2d51ba144495cbf8e43a93d658c2302b5b097b795bedefa221d1852961947ac91347023d7ad8e6aa23f0ce2e1a52d8c3e06b19557e9ca20e549d10d62a2abcf6c5a8268fc7d4ea47bcacd0056bc91a250fdcfda66a4ae82544c77cf14fae81cfe35e449f4592646f1a188c14794b972c462328ce1cfad3e31f6845820c8202c3096494fcb4d9625e1d9ca1e485475fba8c40da28ead22454b0fbbe00f7290fcaa1c2d3936830dffcaf604ca696ae4b3829a25b00df61f1980626afe6d36abb02f74fbe63b8835057d538d7bcb409ed2454318bb1e44d61480e05f9fbb971d9acf00ddd7517f90a8753827366e08cb5ed1c5e7df7ef0391eccac5cfff4858b4444734d1198321ce63ab3d04b2ec11a1c04d1d5b01cc86ab8a8e0ad5e78e0e5
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
# smb2_func.inc
# Revision: 1.15
#

global_var sha_k, null_signature;

null_signature = crap(data:'\0', length:16);

# Leave room for the smb2 header
SMB2_MAX_OUTPUT_RESPONSE = 0xFFFF - 110;

SMB2_FLAGS_SIGNED     = 8;

SMB2_0_IOCTL_IS_FSCTL  = 1;

FSCTL_PIPE_TRANSCEIVE  = 0x0011C017;

SMB2_RESTART_SCANS       = 0x01;
SMB2_RETURN_SINGLE_ENTRY = 0x02;
SMB2_INDEX_SPECIFIED     = 0x04;
SMB2_REOPEN              = 0x10;

SMB2_0_INFO_FILE         = 0x01;
SMB2_0_INFO_FILESYSTEM   = 0x02;
SMB2_0_INFO_SECURITY     = 0x03;
SMB2_0_INFO_QUOTA        = 0x04;

#==================================================================#
# Section 1. Crypto                                                #
#==================================================================#

sha_k = make_list(
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
);

#==================================================================#
# Section 2. Utilities                                             #
#==================================================================#

#---------------------------------------------------------#
# Function    : mklist                                    #
# Description : Generates a list                          #
#---------------------------------------------------------#

function mklist()
{
 local_var ret;
 local_var i, l;

 l = max_index (_FCT_ANON_ARGS);

 if ( defined_func("fill_list") )
  ret  = fill_list(length:l, value:0);

 for (i=0 ; i<l ; i++)
   ret[i] = _FCT_ANON_ARGS[i];

 return ret;
}


#---------------------------------------------------------#
# Function    : raw_qword                                 #
# Description : Converts a DWORD to a raw little endian   #
#               QWORD                                     #
#---------------------------------------------------------#

function raw_qword(q)
{
  return raw_dword(d:q) + raw_dword(d:0);
}

#---------------------------------------------------------#
# Function    : get_qword                                 #
# Description : Reads a QWORD in a buffer and converts it #
#               to a DWORD                                #
#---------------------------------------------------------#

function get_qword(blob, pos)
{
  return get_dword(blob:blob, pos:pos);
}

#==================================================================#
# Section 3. SMB2 Code                                             #
#==================================================================#

#---------------------------------------------------------#
# Function    : smb2_header                               #
# Description : Returns an encoded SMB header without     #
#               the signature                             #
#---------------------------------------------------------#

function smb2_header(command, status, flags)
{
  local_var header, fl;

  if (isnull(flags))
    flags = 0;

  header = '\xFESMB'                             + # ProtocolId
           raw_word(w:64)                        + # StructureSize
           raw_word(w:0)                         + # Epoch
           raw_dword(d:status)                   + # Status
           raw_word(w:command)                   + # Command
           raw_word(w:126)                       + # Credits
           raw_dword(d:flags)                    + # Flags
           raw_dword(d:0)                        + # NextCommand
           raw_qword(q:session_get_messageid())  + # MessageId
           raw_dword(d:session_get_pid())        + # ProcessId
           raw_dword(d:session_get_tid())        + # TreeId
           session_get_sid();                      # SessionId

  return header;
}

#---------------------------------------------------------#
# Function    : smb2_decode_header                        #
# Description : Decodes a SMB2 header                     #
#---------------------------------------------------------#

function smb2_decode_header(header)
{
  local_var ret;

  ret = NULL;

  ret[0]  = substr( header, 0, 3);           # ProtocolId (\xFESMB)
  ret[1]  = get_word(  blob:header, pos:4);  # Header Length
  ret[2]  = get_word(  blob:header, pos:6);  # Credit Charge
  ret[3]  = get_dword( blob:header, pos:8);  # Status
  ret[4]  = get_word(  blob:header, pos:12); # Command
  ret[5]  = get_word(  blob:header, pos:14); # Credits Granted
  ret[6]  = get_word(  blob:header, pos:16); # Flags
  ret[7]  = get_word(  blob:header, pos:20); # Next Command Offset
  ret[8]  = get_qword( blob:header, pos:24); # Message ID
  ret[9]  = get_dword( blob:header, pos:32); # Process ID
  ret[10] = get_dword( blob:header, pos:36); # Tree ID
  ret[11] = substr( header, 40, 47);         # Session ID
  ret[12] = substr( header, 48, 63);         # Signature

  return ret;
}

#---------------------------------------------------------#
# Function    : decode_smb2                               #
# Description : Decodes a SMB2 packet                     #
#---------------------------------------------------------#

function decode_smb2(data)
{
  local_var header, length;
  local_var key, tohash, hash;

  length = strlen(data);

  header = smb2_decode_header(header:substr(data, 0, 63));

  key = session_get_mackey();
  if (key && header[3] != STATUS_PENDING)
  {
    tohash = substr(data, 0, 47) + null_signature + substr(data, 64, length-1);
    hash = HMAC_SHA256(key:key, data:tohash);

    if (substr(hash, 0, 15) != header[12])
      return NULL;
  }

  if (length > 64)
    data = substr(data, 64, length-1);
  else
    data = NULL;

  return mklist(header, data);

}

#---------------------------------------------------------#
# Function    : smb2_recv                                 #
# Description : Receives and decodes a SMB2 packet        #
#---------------------------------------------------------#

function smb2_recv ()
{
  local_var socket, timeout, length, trailer, ret, header;

  socket = session_get_socket ();
  timeout = session_get_timeout ();

  length = recv(socket:socket, length:4, min:4, timeout:timeout);
  if (strlen(length) != 4)
    return NULL;

  length = 65535 * ord(length[1]) +
           256 * ord(length[2]) +
           ord(length[3]);

  if (length < 64)
    return NULL;

  if (length > 100000)
    length = 100000;

  trailer = recv(socket:socket, length:length, min:length, timeout:timeout);
  if (strlen(trailer) < length )
    return NULL;

  ret = decode_smb2(data:trailer);
  if (isnull(ret))
    return NULL;

  header = ret[0];

  # the server must not send anything before the reply as we are not asynchronous
  if (header[3] == STATUS_PENDING)
    return smb2_recv();

  return ret;
}

#---------------------------------------------------------#
# Function    : smb2_sendrecv                             #
# Description : Sends and receives a SMB2 packet          #
#---------------------------------------------------------#

function smb2_sendrecv(command, data)
{
  local_var header, netbios, socket, length, signature, key;

  key = session_get_mackey();
  if (key)
  {
    header = smb2_header(command:command, status:STATUS_SUCCESS, flags:SMB2_FLAGS_SIGNED);
    signature = HMAC_SHA256(key:key, data:header+null_signature+data);
    header = header + substr(signature,0,15);
  }
  else
  {
    header = smb2_header(command:command, status:STATUS_SUCCESS) + null_signature;
  }

  length = strlen(header) + strlen(data);

  netbios = netbios_header (type:0, length:length) +
  header + data;

  socket = session_get_socket();
  send (socket:socket, data:netbios);

  if (session_get_mackey())
    session_increase_sequencenumber();

  return smb2_recv ();
}

#---------------------------------------------------------#
# Function    : smb2_session_setup                        #
# Description : Performs a SMB2 session setup             #
#---------------------------------------------------------#

function smb2_session_setup(login, password, hash, domain)
{
  local_var data, ret, securityblob, header, length;
  local_var challenge, d_name, flags, mackey, secmode;

  securityblob = ntlmssp_negotiate_securityblob ();

  data = raw_word( w:25)                   + # StructureSize
         raw_byte( b:0)                    + # VcNumber
         raw_byte( b:1)                    + # SecurityMode
         raw_dword(d:0)                    + # Capabilities
         raw_dword(d:0)                    + # Channel
         raw_word( w:88)                   + # SecurityBufferOffset
         raw_word( w:strlen(securityblob)) + # SecurityBufferLength
         raw_qword(q:0)                    + # PreviousSessionId
         securityblob;                       # Buffer

  ret = smb2_sendrecv(command:SMB2_SESSION_SETUP, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];
  if (header[3] != STATUS_MORE_PROCESSING_REQUIRED)
    return NULL;

  session_set_sid(sid:header[11]);

  data = ret[1];
  if (strlen(data) < 8)
    return NULL;

  length = get_word(blob:data, pos:6);
  if (strlen(data) < (length+8))
    return NULL;

  securityblob = substr(data, 8, length+7);

  challenge = ntlmssp_parse_challenge (data:securityblob);
  if (isnull(challenge))
    return NULL;

  session_set_addrlist(addrlist:challenge[2]);

  d_name = get_string2 (blob:challenge[1], pos:0, len:strlen(challenge[1]));
  challenge = challenge[0];

  session_set_host_info (domain:d_name, os:NULL, lan:NULL);

  if (login)
  {
    if (password)
      password = cstring (string:password, _null:1);
      login = cstring (string:login, _null:1);
      domain = cstring (string:domain, _null:1);
  }
  else
  {
    login = password = domain = hash = NULL;
  }

  securityblob = ntlmssp_auth_securityblob (password:password,login:login,hash:hash,domain:domain,challenge:challenge);
  if (isnull(securityblob))
    return NULL;

  mackey = securityblob[0];
  securityblob = securityblob[1];

  secmode = session_get_secmode();

  data = raw_word( w:25)                   + # StructureSize
         raw_byte( b:0)                    + # VcNumber
         raw_byte( b:secmode)              + # SecurityMode
         raw_dword(d:0)                    + # Capabilities
         raw_dword(d:0)                    + # Channel
         raw_word( w:88)                   + # SecurityBufferOffset
         raw_word( w:strlen(securityblob)) + # SecurityBufferLength
         raw_qword(q:0)                    + # PreviousSessionId
         securityblob;                       # Buffer

  ret = smb2_sendrecv(command:SMB2_SESSION_SETUP, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];
  if (header[3] != STATUS_SUCCESS)
    return NULL;

  if (secmode)
    session_set_mackey(key:mackey);

  data = ret[1];
  if (strlen(data) < 8)
    return NULL;

  length = get_word(blob:data, pos:6);
  if (strlen(data) < (length+8))
    return NULL;

  securityblob = substr(data, 8, 8+length-1);

  flags = get_word(blob:data, pos:6);

  challenge = ntlmssp_parse_response (data:securityblob);
  if (isnull(challenge) || (challenge != 0)) # Accept Completed
    return NULL;

  return flags;
}

#---------------------------------------------------------#
# Function    : smb2_session_setup                        #
# Description : Performs a SMB2 session setup             #
#---------------------------------------------------------#

function smb2_session_setup_kerberos(login, password, realm, host)
{
  local_var data, ret, securityblob, header, length;
  local_var challenge, d_name, flags, mackey, secmode;
  local_var kerb_data, key;

  securityblob = ntlmssp_negotiate_securityblob ();

  kerb_data = kerberos_securityblob (login:login,password:password,realm:realm,host:host);
  if (isnull(kerb_data))
    return NULL;

  securityblob = kerb_data[1];

  data = raw_word( w:25)                   + # StructureSize
         raw_byte( b:0)                    + # VcNumber
         raw_byte( b:1)                    + # SecurityMode
         raw_dword(d:0)                    + # Capabilities
         raw_dword(d:0)                    + # Channel
         raw_word( w:0x58)                 + # SecurityBufferOffset
         raw_word( w:strlen(securityblob)) + # SecurityBufferLength
         raw_qword(q:0)                    + # PreviousSessionId
         securityblob;                       # Buffer

  ret = smb2_sendrecv(command:SMB2_SESSION_SETUP, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];
  if (header[3] != STATUS_SUCCESS)
    return NULL;

  session_set_sid(sid:header[11]);

  data = ret[1];
  if (strlen(data) < 8)
    return NULL;

  length = get_word(blob:data, pos:6);
  if (strlen(data) < (length+8))
    return NULL;

  securityblob = substr(data, 8, length+7);
  key = check_kerberos_response (data:securityblob, key:kerb_data[0]);
  if (isnull(key))
    return NULL;

  secmode = session_get_secmode();

  if (secmode)
  {
    if (key[0] == 0)
    session_set_mackey (key:kerb_data[0]);
    else
    session_set_mackey (key:key[1]);
  }

  return data;
}

#---------------------------------------------------------#
# Function    : smb2_tree_connect                         #
# Description : Performs a SMB2 tree connect              #
#---------------------------------------------------------#

function smb2_tree_connect(path)
{
  local_var data, ret, header;

  path = cstring (string:"\\", _null:1) + cstring (string:session_get_hostname(), _null:1) + cstring (string:"\", _null:1) + cstring (string:path, _null:1);

  data = raw_word(w:9)            + # StructureSize
         raw_word(w:0)            + # Reserved
         raw_word(w:0x48)         + # PathOffset
         raw_word(w:strlen(path)) + # PathLength
         path;                      # Buffer

  ret = smb2_sendrecv(command:SMB2_TREE_CONNECT, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];
  if (header[3] != STATUS_SUCCESS)
    return NULL;

  session_set_tid(tid:header[10]);

  data = ret[1];
  if (strlen(data) != 16)
    return NULL;

  ret = NULL;
  ret[0] = get_word( blob:data, pos:0);  # StructureSize
  ret[1] = get_byte( blob:data, pos:2);  # ShareType
  ret[2] = get_byte( blob:data, pos:3);  # Reserved
  ret[3] = get_dword(blob:data, pos:4);  # ShareFlags
  ret[4] = get_dword(blob:data, pos:8);  # Capabilities
  ret[5] = get_dword(blob:data, pos:12); # MaximalAccess

  return ret;
}

#---------------------------------------------------------#
# Function    : smb2_connect                              #
# Description : Performs a SMB2 connect                   #
#---------------------------------------------------------#

function smb2_create(name, desired_access, flags_attributes, share_mode, create_disposition, create_options)
{
  local_var data, ret, header, name_len;

  if(isnull(name) || name =="")
  {
    # [MS-SMB2] section 2.2.13
    # "In the request, the Buffer field MUST be at least one byte in length."
    name = raw_string(0x00);

    # [MS-SMB2] section 2.2.13
    # "A zero length file name indicates a request to open the root of the share."
    name_len = 0;
  }
  else
  {
    # Remove any preceding or terminating path separators (Per [MS-FSCC] 2.1.5)
    name = ereg_replace(string:name, pattern:"^([\/\\]*)(.*\w)([\/\\]*)$", replace:"\2");

    name = cstring(string:name, _null:1);
    name_len = strlen(name);
  }

  data = raw_word( w:0x39)               + # StructureSize
         raw_byte( b:0)                  + # SecurityFlags
         raw_byte( b:0)                  + # RequestedOplockLevel
         raw_dword(d:2)                  + # ImpersonationLevel
         raw_qword(q:0)                  + # SmbCreateFlags
         raw_qword(q:0)                  + # Reserved
         raw_dword(d:desired_access)     + # DesiredAccess
         raw_dword(d:flags_attributes)   + # FileAttributes
         raw_dword(d:share_mode)         + # ShareAccess
         raw_dword(d:create_disposition) + # CreateDisposition
         raw_dword(d:create_options)     + # CreateOptions
         raw_word( w:0x78)               + # NameOffset
         raw_word( w:name_len)           + # NameLength
         raw_dword(d:0)                  + # CreateContextsOffset
         raw_dword(d:0)                  + # CreateContextsLength
         name;                             # Buffer

  ret = smb2_sendrecv(command:SMB2_CREATE, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];
  if (header[3] != STATUS_SUCCESS)
    return NULL;

  data = ret[1];
  if (strlen(data) != 88)
    return NULL;

  ret = NULL;
  ret[0] = substr(data, 64, 79); # FileId
  ret[1] = substr(data, 48, 63); # EndofFile

  return ret;
}

#---------------------------------------------------------#
# Function    : smb2_write                                #
# Description : Writes to a pipe/file                     #
#---------------------------------------------------------#

function smb2_write(fid, offset, mode, data)
{
  local_var ret, header;

  data = raw_word( w:0x31)         + # StructureSize
         raw_word( w:0x70)         + # DataOffset
         raw_dword(d:strlen(data)) + # Length
         raw_qword(q:offset)       + # Offset
                     fid           + # FileId
         raw_dword(d:0)            + # Channel
         raw_dword(d:0)            + # RemainingBytes
         raw_word( w:0)            + # WriteChannelInfoOffset
         raw_word( w:0)            + # WriteChannelInfoLength
         raw_dword(d:0)            + # Flags
         data;                       # Buffer

  ret = smb2_sendrecv(command:SMB2_WRITE, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];
  if (header[3] != STATUS_SUCCESS)
    return NULL;

  data = ret[1];
  if (strlen(data) < 16)
    return NULL;

  ret = NULL;
  ret[0] = get_word(blob: data, pos:0);  # StructureSize
  ret[1] = get_word(blob: data, pos:2);  # Reserved
  ret[2] = get_dword(blob:data, pos:4);  # Count
  ret[3] = get_dword(blob:data, pos:8);  # Remaining
  ret[4] = get_word(blob: data, pos:12); # WriteChannelInfoOffset
  ret[5] = get_word(blob: data, pos:14); # WriteChannelInfoLength

  return ret;
}

#---------------------------------------------------------#
# Function    : smb2_read                                 #
# Description : Reads from a pipe/file                    #
#---------------------------------------------------------#

function smb2_read(fid, offset, length)
{
  local_var data, ret, header, pos;

  data = raw_word( w:0x31)   + # StructureSize
         raw_byte( b:0)      + # Padding
         raw_byte( b:0)      + # Reserved
         raw_dword(d:length) + # Length
         raw_qword(q:offset) + # Offset
                     fid     + # FileId
         raw_dword(d:0)      + # MininumCount
         raw_dword(d:0)      + # Channel
         raw_dword(d:0)      + # RemainingBytes
         raw_word( w:0)      + # WriteChannelInfoOffset (Reserved through 2.1)
         raw_word( w:0)      + # WriteChannelInfoLength (Reserved through 2.1)
         raw_byte( b:0);       # Buffer

  ret = smb2_sendrecv(command:SMB2_READ, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];
  if (header[3] != STATUS_SUCCESS && header[3] != STATUS_BUFFER_OVERFLOW)
    return NULL;

  data = ret[1];
  if (strlen(data) < 16)
    return NULL;

  ret = NULL;
  ret[0] = get_word( blob:data, pos:0);  # StructureSize
  ret[1] = get_byte( blob:data, pos:2);  # DataOffset
  ret[2] = get_byte( blob:data, pos:3);  # Reserved
  ret[3] = get_dword(blob:data, pos:4);  # DataLength
  ret[4] = get_dword(blob:data, pos:8);  # DataRemaining
  ret[5] = get_dword(blob:data, pos:12); # Reserved2

  if (ret[3] > 0)
  {
    pos = ret[1] - 0x40;
    ret[6] = substr(data, pos, pos+ret[3]-1);
  }
  else
    ret[6] = NULL;

  return ret[6];
}

#---------------------------------------------------------#
# Function    : smb2_ioctl                                #
# Description : Performs a IOCTL operation on the file    #
#               descriptor                                #
#---------------------------------------------------------#

function smb2_ioctl(fid, code, data)
{
  local_var ret, header, type, pos, max_resp_size;

  if (code == FSCTL_PIPE_TRANSCEIVE)
    type = SMB2_0_IOCTL_IS_FSCTL;

  #MaxOutputResponse = MaxTransactSize - sizeof(dcerpc structure);
  max_resp_size = session_get_buffersize() - 0x400;
  if (max_resp_size < 1024) max_resp_size = 1024;

  data = raw_word( w:0x39)          + # StructureSize
         raw_word( w:0)             + # Reserved
         raw_dword(d:code)          + # CtlCode
                     fid            + # FileId
         raw_dword(d:0x78)          + # InputOffset
         raw_dword(d:strlen(data))  + # InputCount
         raw_dword(d:0)             + # MaxInputResponse
         raw_dword(d:0)             + # OutputOffset
         raw_dword(d:0)             + # OutputCount
         raw_dword(d:max_resp_size) + # MaxOutputResponse
         raw_dword(d:type)          + # Flags
         raw_dword(d:0)             + # Reserved2
         data;                        # Buffer

  ret = smb2_sendrecv(command:SMB2_IOCTL, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];
  if (header[3] != STATUS_SUCCESS)
    return NULL;

  data = ret[1];
  if (strlen(data) < 48)
    return NULL;

  ret = NULL;
  ret[0] = get_word(blob:data,  pos:0);  # StructureSize
  ret[1] = get_word(blob:data,  pos:2);  # Reserved
  ret[2] = get_dword(blob:data, pos:4);  # CtlCode
  ret[3] = substr(data, 8, 23);          # FileId
  ret[4] = get_dword(blob:data, pos:24); # InputOffset
  ret[5] = get_dword(blob:data, pos:28); # InputCount
  ret[6] = get_dword(blob:data, pos:32); # OutputOffset
  ret[7] = get_dword(blob:data, pos:36); # OutputCount
  ret[8] = get_dword(blob:data, pos:40); # Flags
  ret[9] = get_dword(blob:data, pos:44); # Reserved2

  if (ret[5] > 0)
  {
    pos = ret[4] - 0x40;
    ret[10] = substr(data, pos, pos+ret[5]-1);
  }
  else
    ret[10] = NULL;

  if (ret[7] > 0)
  {
    pos = ret[6] - 0x40;
    ret[11] = substr(data, pos, pos+ret[7]-1);
  }
  else
    ret[11] = NULL;

  return ret;
}

#---------------------------------------------------------#
# Function    : smb2_close                                #
# Description : Closes the file descriptor                #
#---------------------------------------------------------#

function smb2_close(fid)
{
  local_var data, ret, header;

  data = raw_word( w:24) + # StructureSize
         raw_word( w:0)  + # Flags
         raw_dword(d:0)  + # Reserved
         fid;              # FileId

  ret = smb2_sendrecv(command:SMB2_CLOSE, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];
  if (header[3] != STATUS_SUCCESS)
    return NULL;

  data = ret[1];
  if (strlen(data) < 60)
    return NULL;

  ret = NULL;
  ret[0] = get_word(blob:data,  pos:0);    # StructureSize
  ret[1] = get_byte(blob:data,  pos:2);    # Flags
  ret[2] = get_dword(blob:data, pos:4);    # Reserved
  ret[3] = convert_win64_time_to_unixtime( # CreationTime
            low  : get_dword (blob:data, pos:8),
            high : get_dword (blob:data, pos:8 + 4)
  );
  ret[4] = convert_win64_time_to_unixtime( # LastAccessTime
            low  : get_dword (blob:data, pos:16),
            high : get_dword (blob:data, pos:16 + 4)
  );
  ret[5] = convert_win64_time_to_unixtime( # LastWriteTime
            low  : get_dword (blob:data, pos:24),
            high : get_dword (blob:data, pos:24 + 4)
  );
  ret[6] = convert_win64_time_to_unixtime( # ChangeTime
            low  : get_dword (blob:data, pos:32),
            high : get_dword (blob:data, pos:32 + 4)
  );
  ret[7] = get_qword(blob:data, pos:40);   # AllocationSize
  ret[8] = get_qword(blob:data, pos:48);   # EndofFile
  ret[9] = get_dword(blob:data, pos:56);   # FileAttributes

  return ret;
}

#---------------------------------------------------------#
# Function    : smb2_tree_disconnect                      #
# Description : Disconnect from the current tree          #
#---------------------------------------------------------#

function smb2_tree_disconnect()
{
  local_var data, ret, header, tid;

  tid = session_get_tid ();
  if (isnull(tid))
    return 1;

  data = raw_word(w:4) + # StructureSize
         raw_word(w:0);  # Reserved

  ret = smb2_sendrecv(command:SMB2_TREE_DISCONNECT, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];
  if (header[3] != STATUS_SUCCESS)
    return NULL;

  data = ret[1];
  if (strlen(data) < 4)
    return NULL;

  ret = NULL;
  ret[0] = get_word(blob:data, pos:0);   # StructureSize
  ret[1] = get_byte(blob:data, pos:2);   # Reserved

  session_set_tid(tid:NULL);

  return ret;
}

#---------------------------------------------------------#
# Function    : smb2_logoff                               #
# Description : Logs off                                  #
#---------------------------------------------------------#

function smb2_logoff()
{
  local_var data, ret, header;

  data = raw_word(w:4) + # StructureSize
         raw_word(w:0);  # Reserved

  ret = smb2_sendrecv(command:SMB2_LOGOFF, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];
  if (header[3] != STATUS_SUCCESS)
    return NULL;

  data = ret[1];
  if (strlen(data) < 4)
    return NULL;

  ret = NULL;
  ret[0] = get_word(blob:data, pos:0);   # StructureSize
  ret[1] = get_byte(blob:data, pos:2);   # Reserved

  return ret;
}

#---------------------------------------------------------#
# Function    : decode_file_directory_info                #
# Description : Decodes a FileDirectoryInformation        #
#               structure                                 #
#---------------------------------------------------------#

function decode_file_directory_info(data)
{
  local_var nextoffset, pos, ret, i, file, len;

  if (!data) return NULL;

  len = strlen(data);
  pos = 0;
  i = 0;
  ret = NULL;

  while (pos < len)
  {
    nextoffset = get_dword(blob:data, pos:pos);
    file = NULL;

    file[0] = get_dword(blob:data, pos:pos+4);   # FileIndex
    file[1] = convert_win64_time_to_unixtime(    # CreationTime
                low  : get_dword (blob:data, pos:pos+8),
                high : get_dword (blob:data, pos:pos+8+4)
    );
    file[2] = convert_win64_time_to_unixtime(    # LastAccessTime
                low  : get_dword (blob:data, pos:pos+16),
                high : get_dword (blob:data, pos:pos+16+4)
    );
    file[3] = convert_win64_time_to_unixtime(    # LastWriteTime
                low  : get_dword (blob:data, pos:pos+24),
                high : get_dword (blob:data, pos:pos+24+4)
    );
    file[4] = convert_win64_time_to_unixtime(    # ChangeTime
                low  : get_dword (blob:data, pos:pos+32),
                high : get_dword (blob:data, pos:pos+32+4)
    );
    file[5] = get_qword(blob:data, pos:pos+40);  # EndOfFile
    file[6] = get_qword(blob:data, pos:pos+48);  # AllocationSize
    file[7] = get_dword(blob:data, pos:pos+56);  # FileAttributes
    file[8] = get_dword(blob:data, pos:pos+60);  # FileNameLength
    file[9] = get_string2 (blob:data, pos:pos+64, len:file[8]);

    pos = pos + nextoffset;
    ret[i++] = file;

    if (nextoffset == 0)
      break;
  }

  return ret;
}

#---------------------------------------------------------#
# Function    : smb2_query_directory                      #
# Description : Queries directory information             #
#---------------------------------------------------------#

function smb2_query_directory(flags, index, pattern, id)
{
  local_var data, ret, header;

  pattern = cstring(string:pattern, _null:1);

  data = raw_word( w:33)                         + # StructureSize
         raw_byte( b:FILE_DIRECTORY_INFORMATION) + # FileInformationClass
         raw_byte( b:flags)                      + # Flags
         raw_dword(d:index)                      + # FileIndex
         id                                      + # FileId
         raw_word( w:0x60)                       + # FileNameOffset
         raw_word( w:strlen(pattern))            + # FileNameLength
         raw_dword(d:4096)                       + # OutputBufferLength
         pattern;

  ret = smb2_sendrecv(command:SMB2_QUERY_DIRECTORY, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];
  if (header[3] != STATUS_SUCCESS)
    return NULL;

  data = ret[1];
  if (strlen(data) < 8)
    return NULL;

  ret = NULL;
  ret[0] = get_word(blob:data, pos:0);   # StructureSize
  ret[1] = get_byte(blob:data, pos:2);   # OutputBufferOffset
  ret[2] = get_dword(blob:data, pos:4);  # OutputBufferLength

  if (strlen(data) < (8+ret[2]))
    return NULL;

  ret[3] = substr(data, 8, 8+ret[2]-1);

  return decode_file_directory_info(data:ret[3]);
}

#---------------------------------------------------------#
# Function    : smb2_query_info                           #
# Description : Queries FID information                   #
#---------------------------------------------------------#

function smb2_query_info(type, class, info, id)
{
  local_var data, ret, header, olen;

  data = raw_word( w:41)    + # StructureSize
         raw_byte( b:type)  + # InfoType
         raw_byte( b:class) + # FileInfoClass
         raw_dword(d:0)     + # OutputBufferLength
         raw_word( w:0)     + # InputBufferOffset
         raw_word( w:0)     + # Reserved
         raw_dword(d:0)     + # InputBufferLength
         raw_dword(d:info)  + # AdditionalInformation
         raw_dword(d:0)     + # Flags
         id;                  # FileId

  ret = smb2_sendrecv(command:SMB2_QUERY_INFO, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];
  if (header[3] != STATUS_BUFFER_TOO_SMALL)
    return NULL;

  data = ret[1];
  if (strlen(data) < 12)
    return NULL;

  olen = get_dword(blob:data, pos:8);

  data = raw_word( w:41)    + # StructureSize
         raw_byte( b:type)  + # InfoType
         raw_byte( b:class) + # FileInfoClass
         raw_dword(d:olen)  + # OutputBufferLength
         raw_word( w:0)     + # InputBufferOffset
         raw_word( w:0)     + # Reserved
         raw_dword(d:0)     + # InputBufferLength
         raw_dword(d:info)  + # AdditionalInformation
         raw_dword(d:0)     + # Flags
         id;                  # FileId

  ret = smb2_sendrecv(command:SMB2_QUERY_INFO, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];
  if (header[3] != STATUS_SUCCESS)
    return NULL;

  data = ret[1];
  if (strlen(data) < 8)
    return NULL;

  ret = NULL;
  ret[0] = get_word( blob:data, pos:0); # StructureSize
  ret[1] = get_byte( blob:data, pos:2); # OutputBufferOffset
  ret[2] = get_dword(blob:data, pos:4); # OutputBufferLength

  if (strlen(data) < (8+ret[2]))
    return NULL;

  ret[3] = substr(data, 8, 8+ret[2]-1);

  return ret;
}

#---------------------------------------------------------#
# Function    : smb2_set_info                             #
# Description : Sets FID information                      #
#---------------------------------------------------------#
function smb2_set_info(type, class, info, id, data)
{
  local_var header, ret;

  data = raw_word( w:33)           + # StructureSize
         raw_byte( b:type)         + # InfoType
         raw_byte( b:class)        + # FileInfoClass
         raw_dword(d:strlen(data)) + # BufferLength
         raw_word( w:0x60)         + # BufferOffset
         raw_word( w:0)            + # Reserved
         raw_dword(d:info)         + # AdditionalInformation
         id                        + # FileId (16 Bytes)
         data;                       # Buffer
  ret = smb2_sendrecv(command:SMB2_SET_INFO, data:data);
  if (isnull(ret))
    return NULL;

  header = ret[0];
  if (header[3] != STATUS_SUCCESS)
    return NULL;

  data = ret[1];
  if (strlen(data) < 2)
    return NULL;

  # If successfull, the server returns an SMB2_SET_INFO packet
  # that only contains a structure size of 2. [MS-SMB2] section 2.2.40
  ret = get_word(blob:data, pos:0); # StructureSize
  if (ret != 2)
    return NULL;

  return TRUE;
}

#---------------------------------------------------------#
# Function    : smb2_negotiate                            #
# Description : Parses SMB2 negotiate response            #
#---------------------------------------------------------#

function smb2_negotiate(data)
{
  local_var ret, header, pos;

  ret = decode_smb2(data:data);

  header = ret[0];
  if (header[3] != STATUS_SUCCESS)
    return NULL;

  data = ret[1];
  if (strlen(data) < 64)
    return NULL;

  ret = NULL;
  ret[0] =  get_word( blob:data, pos:0);    # StructureSize
  ret[1] =  get_word( blob:data, pos:2);    # SecurityMode
  ret[2] =  get_word( blob:data, pos:4);    # DialectRevision
  ret[3] =  get_word( blob:data, pos:6);    # Reserved
  ret[4] =  substr(data, 8, 23);            # ServerGuid
  ret[5] =  get_dword(blob:data, pos:24);   # Capabilities
  ret[6] =  get_dword(blob:data, pos:28);   # MaxTransactSize
  ret[7] =  get_dword(blob:data, pos:32);   # MaxReadSize
  ret[8] =  get_dword(blob:data, pos:36);   # MaxWriteSize
  ret[9] =  convert_win64_time_to_unixtime( # SystemTime
              low  : get_dword (blob:data, pos:40),
              high : get_dword (blob:data, pos:40 + 4)
  );
  ret[10] = convert_win64_time_to_unixtime( # ServerStartTime
              low  : get_dword (blob:data, pos:48),
              high : get_dword (blob:data, pos:48 + 4)
  );
  ret[11] = get_word( blob:data, pos:56);   # SecurityBufferOffset
  ret[12] = get_word( blob:data, pos:58);   # SecurityBufferLength
  ret[13] = get_dword(blob:data, pos:60);   # Reserved2

  if (ret[12] > 0)
  {
    pos = ret[11] - 0x40;
    ret[14] = substr(data, pos, pos+ret[12]-1);
  }
  else
    ret[14] = NULL;

  return ret;
}

#---------------------------------------------------------#
# Function    : smb2_login                                #
# Description : Logs in using SMB2 protocol               #
#---------------------------------------------------------#

function smb2_login (negotiate,login,password,domain,lm_hash,ntlm_hash)
{
  local_var ret;
  local_var SecurityMode, Capabilities, SecurityBlob, MaxBufferSize;
  local_var spnego, michlist, host, realm, Extended;
  local_var hash;
  local_var only_kerb;

  if (!isnull(ntlm_hash))
    hash = ntlm_hash;
  else
    hash = NULL;

  ret = smb2_negotiate(data:negotiate);
  if (isnull(ret))
    return NULL;

  session_set_smb2(flag:TRUE);
  session_set_unicode(unicode:1);

  SecurityMode = ret[1];
  Capabilities = ret[5];
  SecurityBlob = ret[14];
  MaxBufferSize = ret[8];

  spnego = der_parse_spnego_init (sdata:SecurityBlob);
  if(
      !isnull(spnego) && (spnego[3] != NULL) &&
      (spnego[3] != "not_defined_in_RFC4178@please_ignore") &&
      (toupper(spnego[3]) != "NONE") # samba
    )
  {
    michlist = spnego[3];
    host = ereg_replace (pattern:"(.*?)\$?@.*", string:michlist, replace:"\1");
    realm = ereg_replace (pattern:".*\$?@(.*)", string:michlist, replace:"\1");
    Extended = 2; # Kerberos
  }
  else if(!isnull (spnego) && (spnego[0] != NULL) && '1.2.840.48018.1.2.2' >< spnego[0])
  {
    # Check if Kerberos is supported by server, if so use it for auth
    # 1.2.840.48018.1.2.2  -> Microsoft Kerberos 5
    # 1.2.840.113554.1.2.2 -> Kerberos 5
    realm  = domain;
    host   =  kb_smb_name();
    if (isnull(host) || host == get_host_ip())
      host = get_host_name();
    Extended = 2;
  }
  else
    Extended = 1;

  # handle message signing only if server requires it
  if (SecurityMode & 2)
    session_set_secmode(mode:SecurityMode);

  if (Capabilities & CAP_EXTENDED_SECURITY)
    session_add_flags2 (flag:SMB_FLAGS2_EXTENDED_SECURITY);

  session_set_server_max_size (size:MaxBufferSize);
  if (MaxBufferSize > (session_get_buffersize() - 0x100))
  {
    if(MaxBufferSize + 0x100 > SMB2_MAX_OUTPUT_RESPONSE)
      session_set_buffersize(size:SMB2_MAX_OUTPUT_RESPONSE);
    else
      session_set_buffersize(size:MaxBufferSize+0x100);
  }
  if((Extended == 2) && defined_func ("open_sock_kdc") && get_kb_item('KerberosAuth/enabled') && login && password && realm)
  {
    ret = smb2_session_setup_kerberos(login:login, password:password, realm:realm, host:host);
    if (!isnull(ret))
      return TRUE;

    only_kerb = get_kb_item ("SMB/only_use_kerberos");
    if (only_kerb)
      return FALSE;
  }

  # Do NTLMSSP  if kerberos fails
  ret = smb2_session_setup(login:login, password:password, hash:hash, domain:domain);
  if (isnull (ret))
    return FALSE;

  return TRUE;
}
