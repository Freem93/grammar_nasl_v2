#TRUSTED 2e3ab320c56b84ae1d9fabb478189df9e93293521ff70b0ecc9687f662f7c186efc0f00894a8b0f5cf07e61c06d599d1fba7a1b5fe55efa128fd1f068eeaaad91c92072be1c8c18d31a187ddc457c0d8a33f25a242e23ad9579e1a8ae080e611ba725d5c0b929c238deef16ddfd52391d5a2468e23e4f63dd5e08b4a5bf2766f71612330848149313b9d582369866e86c75aa44f6c144290ac5d29e187023d82ff4d446344470fdcf44cbafa2ae11f305e241fee4385065341b6a64f398814976146f2b2b08291b3c969ff47f4623d14d3fa9dda88f6d4f28dc5bd1b0f87780fd1bf198499a535644130a25a3a5f707ec2c14383423043bc61e5f985c53657bb50e8fdb4e2e3c61ff87326ac388d32127b6911b454bdad2c30f5f5154f9c38d194eb84198506a37c5eabf8aa442266e377a09294690553267a14053ef6a170d300b0f205e1ffe572eb4a76363f566141d22b977a727e027337ba4172c7028e227212504688f5e9e9de261a4eead5a3b3a65639e1c74fa212b4e45071f992a648a302d3c83468edf3daca65cbd62efe51b577898e4b6762709d84dcc6421e6644649dcfc5c77bfab615fb08e9d32caf18c0b13e353b91106c3ae9ddad9b0c2d08a779c659cf3bc946a84eba0b0cee6b0dd983b9b8433d16abf3057cd31e758fdb21e4d9beb84af19ffc3c2837dfb71a1ac441f3bc352e177331498db248f93f12
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
# smb_dcerpc.inc
# Revision: 1.12
#

function dce_rpc (type,cid,data,flags,auth_header,auth_data)
{
 local_var packet, flag, alen, flen;

 if (isnull(flags))
   flag = 3; # FIRST fragment, LAST fragment
 else
   flag = flags;


 if (!isnull(auth_data))
 {
  alen = strlen(auth_data);
  flen = 16 + strlen(data) + alen + strlen (auth_header);
 }
 else
 {
  alen = 0;
  flen = 16 + strlen(data);
  auth_data = auth_header = NULL;
 }

 packet = raw_byte (b:5) +                # version
          raw_byte (b:0) +                # version (minor)
	  raw_byte (b:type) +             # packet type
	  raw_byte (b:flag) +             # packet flags
	  raw_dword (d:16) +              # data representation (little-endian/ascii)
	  raw_word (w:flen) +             # Frag length
	  raw_word (w:alen) +             # auth length
	  raw_dword (d:cid) +             # caller ID
	  data +
          auth_header +
          auth_data;

 return packet;
}


function dce_rpc_ntlmssp_header (code)
{
 local_var header;

 header =
	  raw_byte (b:10)   +       # Auth type: NTLMSSP
	  raw_byte (b:code) +       # Auth level
	  raw_byte (b:0)    +       # Auth pad length: 0
	  raw_byte (b:0)    +       # Reserved
	  raw_dword (d:0);          # Auth context id (to randomize for multiple sessions)

 return header;
}


function dce_rpc_bind (cid, uuid, vers, auth)
{
 local_var packet, auth_header, auth_data;
 
 packet = raw_word (w:4280) +       # Max Xmit Frag
          raw_word (w:4280) +       # Max recv Frag
	  raw_dword (d:0)   +       # Assoc group
	  raw_dword (d:1)   +       # Num context items
	  raw_word (w:0)    +       # Context ID
	  raw_word (w:1)    +       # num trans item
	  encode_uuid (uuid:uuid) + # Interface uuid
	  raw_word (w:vers)    +       # interface version
	  raw_word (w:0)    +       # interface version (minor)
	  encode_uuid (uuid:"8a885d04-1ceb-11c9-9fe8-08002b104860") +
	  raw_dword (d:2) ;         # syntax version

 if (!isnull(auth) && (auth == TRUE))
 {
  auth_header = dce_rpc_ntlmssp_header (code:NTLMSSP_CONNECT);
  auth_data = raw_ntlmssp_negotiate();
 }
 else
 {
  auth_data = auth_header = NULL;
 }

 return dce_rpc (type:DCE_RPC_BIND, cid:cid, data:packet, auth_header:auth_header, auth_data:auth_data);
}



function dce_rpc_parse_bind_ack (data, auth, cid)
{
 local_var len, res, ret, ntlmssp, pos, pad_len;

 if (strlen (data) < 26)
   return NULL;
 len = get_word (blob:data, pos:24);
 if ((len%2) != 0)
   len += 1; # byte padding

 if (strlen (data) < (26+len+4))
   return NULL;

 res = get_word (blob:data, pos:26+len+4); # error code

 # if no auth, returns the value for compatibility
 if (isnull(auth) || (auth == FALSE))
   return res;

 ret = NULL;
 ret[0] = res;

 if (res != 0)
   return ret;

 ret[1] = get_word (blob:data, pos:20);  # association group

 if (strlen (data) < 26+len+4+32)
   return NULL;

 pos = 26+len+4+26;
 pad_len = get_byte (blob:data, pos:pos);

 pos += 6 + pad_len;

 ntlmssp = substr(data, pos, strlen(data)-1);
 if (isnull(ntlmssp))
   return NULL;

 ntlmssp = raw_ntlmssp_parse_challenge (data:ntlmssp);

 if (isnull(ntlmssp))
   return NULL;

 ret[2] = ntlmssp[0];
 ret[3] = cid;

 return ret;
}

function dce_rpc_alter_context (cid, uuid, vers)
{
 local_var packet, auth_header, auth_data;
 
 packet = raw_word (w:4280) +       # Max Xmit Frag
          raw_word (w:4280) +       # Max recv Frag
	  raw_dword (d:0)   +       # Assoc group
	  raw_dword (d:1)   +       # Num context items
	  raw_word (w:0)    +       # Context ID
	  raw_word (w:1)    +       # num trans item
	  encode_uuid (uuid:uuid) + # Interface uuid
	  raw_word (w:vers)    +       # interface version
	  raw_word (w:0)    +       # interface version (minor)
	  encode_uuid (uuid:"8a885d04-1ceb-11c9-9fe8-08002b104860") +
	  raw_dword (d:2) ;         # syntax version

 auth_data = auth_header = NULL;

  auth_header = dce_rpc_ntlmssp_header (code:NTLMSSP_CONNECT);
  auth_data = raw_dword (d:1) + crap(data:raw_string(0), length:12);

 return dce_rpc (type:DCE_RPC_ALTER, cid:cid, data:packet, auth_header:auth_header, auth_data:auth_data);
}


function dce_rpc_auth3 (cid, login, password, domain, challenge)
{
 local_var packet, auth_header, auth_data;
 
 packet = raw_word (w:4280) +       # Max Xmit Frag
          raw_word (w:4280) ;       # Max recv Frag

 auth_header = dce_rpc_ntlmssp_header (code:NTLMSSP_CONNECT);
 auth_data = raw_ntlmssp_auth_securityblob (password:password, login:login, domain:domain, challenge:challenge);

 return dce_rpc (type:DCE_RPC_AUTH3, cid:cid, data:packet, auth_header:auth_header, auth_data:auth_data[0]);
}


function dce_rpc_connect (socket, cid, uuid, vers, login, password, domain)
{
 local_var ret, resp, pass, name, dom;

 ret = dce_rpc_bind(cid:cid, uuid:uuid, vers:vers, auth:TRUE);

 send (socket:socket, data:ret);
 resp = recv (socket:socket, length:4096);

 if (!resp)
   return NULL;

 resp = dce_rpc_parse_bind_ack (data:resp, cid:cid, auth:TRUE);
 if (isnull (resp))
   return NULL;

 pass = cstring (string:password, _null:1);
 name = cstring (string:login, _null:1);
 dom = cstring (string:domain, _null:1);  

 ret = dce_rpc_auth3 (cid:cid, login:name, password:pass, domain:dom, challenge:resp[2]);
 send (socket:socket, data:ret);

 return resp;
}



function dce_rpc_request (code, data, flags, id, auth, type)
{
 local_var packet, cid, auth_header, auth_data;

 if (!isnull(auth) && (auth == TRUE))
 {
  auth_header = dce_rpc_ntlmssp_header (code:NTLMSSP_CONNECT);
  auth_data = raw_dword (d:1) + crap(data:raw_string(0), length:12);
  cid = id;
 }
 else
 {
  if (isnull(id))
    cid = session_get_cid();
  else
    cid = id;

  auth_header = auth_data = NULL;
 }

 # this is an edge case where we wanted to control the type field
 if (isnull(type)) type = DCE_RPC_REQUEST;

 packet = raw_dword (d:strlen(data))  +       # Alloc hint
          raw_word (w:0)              +       # Context ID
	  raw_word (w:code)           +       # Opnum
          data;
 
 return dce_rpc (type:type, cid:cid, data:packet, flags:flags, auth_header:auth_header, auth_data:auth_data);
}



function dce_rpc_sendrecv_request (socket, id, code, data, flags)
{
 local_var req, ret;

 req = dce_rpc_request (code:code, data:data, flags:flags, id:id, auth:dcerpc_auth);
 send (socket:socket, data:req);
 ret = recv (socket:socket, length:4096);

 return ret;
}


function dce_rpc_pipe_request (fid, code, data, type)
{
 local_var tmp, rep, len, flag, ret, offset, cid, dat, size, data_len;

 size = session_get_server_max_size() - 110;
 cid = session_get_cid();
 offset = 0;
 data_len = strlen(data);

 if (data_len > size)
 {
   flag = 1; # FIRST fragment
   tmp = substr (data, 0, size-1);
   len = size;
 }
 else
 {
   flag = 3; # FIRST fragment, LAST fragment
   tmp = data;
   len = data_len;
 }

 while (len < data_len)
 {
  ret = smb_write_and_x (fid:fid, offset:offset, mode:WRITE_START, data:dce_rpc_request (code:code, data:tmp, flags:flag, id:cid));
  if (isnull (ret) || (ret != 1))
    return NULL;

  offset += strlen(tmp);

  if ((len + size) < data_len)
  {
   flag = 0;
   tmp = substr (data, len, len+size-1);
   len += size;
  }
  else
  {
   flag = 2;
   tmp = substr (data, len, data_len-1);
   break;
  }
 }

 ret = smb_trans_pipe (fid:fid, data:dce_rpc_request (code:code, data:tmp, flags:flag, id:cid, type:type));
 if (isnull (ret))
   return NULL;

 return ret;
}


function dce_rpc_parse_response (fid, data)
{
 local_var resp, flag, len, alloc, tmp, dat, type;

 if (strlen (data) < 24)
   return NULL;
   
 type = get_byte (blob:data, pos:2);

 # Fault -> return NULL
 if (type == 3)
   return NULL;

 flag = get_byte (blob:data, pos:3);
 len = get_word (blob:data, pos:8) - 24;
 alloc = get_dword (blob:data, pos:16);

 

 if (strlen (data) < (24 + len))
   return NULL;
   
 resp = substr (data, 24, 24 + len - 1);

 # If it is not the last dce_rpc packet we continue to read
 while (!(flag & 2))
 {
  # we read only 1000 bytes at a time
  tmp = smb_read_and_x (fid:fid, offset:0, length:1024);
  if (strlen (tmp) < 24)
    return NULL;

  flag = get_byte (blob:tmp, pos:3);
  len = get_word (blob:tmp, pos:8);
  alloc = get_dword (blob:tmp, pos:16);

  while (strlen (tmp) < len)
  {
   dat = smb_read_and_x (fid:fid, offset:0, length:1024);
   if (!dat)
     return NULL;
   tmp += dat;
  }
  
  resp += substr (tmp, 24, 24 + len - 1);
 }

 return resp;
}


function bind_pipe (pipe, uuid, vers)
{
 local_var fid, ret, data;

 ret = smb_create_and_x (name:pipe,
                         desired_access:FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                         flags_attributes:0,
                         share_mode:0,
                         create_disposition:OPEN_EXISTING,
                         create_options:0x00400040);
 if (isnull(ret))
   return NULL;
 
 fid = ret[0];

 ret = smb_write_and_x (fid:fid, offset:0, mode:WRITE_START, data:dce_rpc_bind(cid:session_get_cid(), uuid:uuid, vers:vers));
 if (isnull (ret) || (ret != 1))
   return NULL;

 data = smb_read_and_x (fid:fid, offset:0, length:1024);
 if (!data)
   return NULL;
 
 ret = dce_rpc_parse_bind_ack (data:data);
 if (isnull (ret) || (ret != 0))
   return NULL;

 return fid;
}


