#TRUSTED 5561f43b000aa52e340d41c99401c840990428e3ca3966693c7fe96c14d575a962756dc081779f2365cafe7b92481c7e53a7128d209401c4691b43938881ab61e1e60009b9cfaeebfc9126182fe93d9779ba1164cb78a9b0852d2b036b6514cc3af7dc1323b83d7725b5d1091f0b57947486aa60c78b2c1295274aac9d5fb05ea8b9b54d6e042648e08d354f5f42f24cab046eb939df02ccdb4859e01f7692b2a88c6a66ab25c0e25e0b29c49835d679c268fdb3b015add38b770896ca32e32dd11b974b9dbdcec990f72efd976f589f8fe04985492661b8c2b1126d31ad455029d3dc2bcc3b6ed3bbd94437012fbc17fa3ee7ebd1e1f113f122adf7b123d25765acc02f8c87392a3a614fb4124a4e81efecce1bb94b2890d2d6556c9058ec84616b2da2189c9610e11bc262d0955ef68178c0060c5934c209af0cc5ce3f6414bdf880f78f9b834e0955198b2c3f72f5e73565fc0754fb7ef23d3ae9e670491ef3f7ecba9599baed7040423e5b9836be49b864e28d2d37d61fbeaf1afe114f06c629af9b950763c06367172ae293b926feaf22a92759b8f870b7d9cb158ae8bf9f05b39b4a277753516790795dd6c5ca99e45ae62b79387094b328acdaefb09edd1f51da9417a3636a09ad6f1214dc85c0c6fb8e7edcbe0edf7bf7c5f1bc84c27fb393ae2640465c14426992e536826edfedc91725ec5d3481ec20407298a63f
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
# smb_cifs.inc
# Revision: 1.23
#



#==================================================================#
# Section 3. SMB functions                                         #
#==================================================================#


#---------------------------------------------------------#
# Function    : smb_parameters                            #
# Description : Create SMB parameters structure           #
#---------------------------------------------------------#

function smb_parameters (data)
{
 local_var count;

 if ( !data )
   count = 0;
 else
   count = strlen (data) / 2;

 return raw_byte (b:count) + data;
}


#---------------------------------------------------------#
# Function    : smb_data                                  #
# Description : Create SMB data structure                 #
#---------------------------------------------------------#

function smb_data (data)
{
 local_var count;

 if ( isnull(data) )
   count = 0;
 else
   count = strlen (data);

 return raw_word (w:count) + data;
}


function netbios_header (type, length)
{
 return raw_byte (b:type) +
        raw_string ( (length>>16) & 255, (length>>8) & 255, (length) & 255 );
}


#---------------------------------------------------------#
# Function    : netbios_packet                            #
# Description : Convert SMB to netbios packet             #
#---------------------------------------------------------#
#                                                         #
# BYTE Type;       # 0 = session message                  #
# BYTE Length[3];  # length is on 24bits                  #
#                                                         #
#---------------------------------------------------------#

function netbios_packet (header,parameters,data)
{
 local_var length, netbios, head, hash, MAC, key;

 key = session_get_mackey();
 
 if (key)
 {
  hash = MD5 (key + header + parameters + data);
  MAC = substr( hash, 0, 7);
  head = substr (header, 0, 13) + MAC + substr (header, 22, 31);
  previous_hash = MAC;
 }
 else
   head = header;

 length = strlen (head) + strlen (parameters) + strlen (data);

 netbios = netbios_header (type:0, length:length) +
           head + parameters + data;

 return netbios;
}


#---------------------------------------------------------#
# Function    : smb_recv                                  #
# Description : Receive network smb packet                #
#---------------------------------------------------------#

function smb_recv ()
{
   local_var header, len, trailer, socket, timeout, tmp, hash, key;

   socket = session_get_socket ();
   if (!socket) return NULL;
   timeout = session_get_timeout ();

   header = recv(socket:socket, length:4, min:4, timeout:timeout);
   if (strlen(header) < 4)
     return(NULL);
   
   len = 65535 * ord(header[1]) +
         256 * ord(header[2]) +
         ord(header[3]);
   
   if (len < 32)
     return (NULL);

   if (len > 100000)
     len = 100000;

   trailer = recv(socket:socket, length:len, min:len, timeout:timeout);
   if (strlen(trailer) < len )
     return(NULL);

   if ( session_get_mackey() )
   {
    key = session_get_mackey();

    tmp = substr (trailer,0,13) + raw_dword (d:session_get_sequencenumber()) + raw_dword (d:0) + substr (trailer, 22, strlen(trailer)-1);
    hash = substr(MD5 (key + tmp),0,7);

    # if signature is not correct we stop
    if (hash >!< substr(trailer, 14, 21))
    {
     if (strlen (key) == 16)
     {
       session_set_mackey (key:crap(data:raw_string(0),length:16));
       tmp = substr (trailer,0,13) + raw_dword (d:session_get_sequencenumber()) + raw_dword (d:0) + substr (trailer, 22, strlen(trailer)-1);
       hash = substr(MD5 (session_get_mackey () + tmp),0,7);

       # guest logon disable smb signing
       if (previous_hash >< substr(trailer, 14, 21))
         session_set_mackey (key:NULL);

       # if signature is not correct we stop
       else if (hash >!< substr(trailer, 14, 21))
         return NULL;
     }
     else
       return NULL;
    }
   }

   if (session_get_mackey())
     session_increase_sequencenumber();

   return trailer;
}


#---------------------------------------------------------#
# Function    : smb_sendrecv                              #
# Description : Perform a client/server exchange          #
#---------------------------------------------------------#

function smb_sendrecv(data)
{
 local_var socket;

 socket = session_get_socket();
 
 if (!socket) return NULL;

 send (socket:socket, data:data);
 
 if (session_get_mackey())
   session_increase_sequencenumber();

 return smb_recv ();
}


#---------------------------------------------------------#
# Function    : get_header_flags                          #
# Description : Extract Flags                             #
#---------------------------------------------------------#

function get_header_flags(header)
{
 return get_byte (blob:header, pos:9);
}


#---------------------------------------------------------#
# Function    : get_header_flags2                         #
# Description : Extract Flags2                            #
#---------------------------------------------------------#

function get_header_flags2(header)
{
 return get_word (blob:header, pos:10);
}


#---------------------------------------------------------#
# Function    : get_header_dos_error_code                 #
# Description : Extract DOS Error code                    #
#---------------------------------------------------------#

function get_header_dos_error_code(header)
{
 return get_word (blob:header, pos:7);
}


#---------------------------------------------------------#
# Function    : get_header_nt_error_code                  #
# Description : Extract NT Error code                     #
#---------------------------------------------------------#

function get_header_nt_error_code(header)
{
 return get_dword (blob:header, pos:5);
}


#---------------------------------------------------------#
# Function    : get_header_command_code                   #
# Description : Extract Command code                      #
#---------------------------------------------------------#

function get_header_command_code(header)
{
 return get_byte (blob:header, pos:4);
}


#---------------------------------------------------------#
# Function    : get_header_uid                            #
# Description : Extract User ID                           #
#---------------------------------------------------------#

function get_header_uid(header)
{
 return get_word (blob:header, pos:28);
}


#---------------------------------------------------------#
# Function    : get_header_tid                            #
# Description : Extract Tree ID                           #
#---------------------------------------------------------#

function get_header_tid(header)
{
 return get_word (blob:header, pos:24);
}


#---------------------------------------------------------#
# Function    : get_header_signature                      #
# Description : Extract Signature                         #
#---------------------------------------------------------#

function get_header_signature(header)
{
 return substr (header,14,21);
}


#---------------------------------------------------------#
# Function    : get_smb_header                            #
# Description : Extract SMB header from blob              #
#---------------------------------------------------------#

function get_smb_header(smbblob)
{
 if (strlen (smbblob) < SMB_HDR_SIZE)
   return NULL;

 return substr (smbblob, 0, SMB_HDR_SIZE - 1);
}


#---------------------------------------------------------#
# Function    : get_smb_parameters                        #
# Description : Extract SMB parameters from blob          #
#---------------------------------------------------------#

function get_smb_parameters(smbblob)
{
 local_var WordCount;

 if (strlen (smbblob) < SMB_HDR_SIZE + 1)
   return NULL;

 WordCount = get_byte (blob:smbblob, pos:SMB_HDR_SIZE);
 if (strlen (smbblob) < (SMB_HDR_SIZE + 1 + WordCount * 2))
   return NULL;

 return substr (smbblob, SMB_HDR_SIZE + 1, SMB_HDR_SIZE + 1 + WordCount * 2);
}


#---------------------------------------------------------#
# Function    : get_smb_data                              #
# Description : Extract SMB data from blob                #
#---------------------------------------------------------#

function get_smb_data(smbblob)
{
 local_var WordCount, ByteCount, pos;

 if (strlen (smbblob) < SMB_HDR_SIZE + 1)
   return NULL;

 WordCount = get_byte (blob:smbblob, pos:SMB_HDR_SIZE);
 if (strlen (smbblob) < (SMB_HDR_SIZE + 1 + WordCount * 2 + 2))
   return NULL;
  
 pos = SMB_HDR_SIZE + 1 + WordCount * 2;
 
 ByteCount = get_word (blob:smbblob, pos:pos);

 if (strlen (smbblob) < (pos + 2 + ByteCount))
   return NULL;

 return substr (smbblob, pos + 2, pos + 2 + ByteCount - 1);
}


#---------------------------------------------------------#
# Function    : smb_header                                #
# Description : Generate header of SMB packet             #
#---------------------------------------------------------#
#                                                         #
# SMB header structure                                    #
#					                  #
# struct {                                                #
#   BYTE  Protocol[4];      # "\xFFSMB"                   #
#   BYTE  Command;                                        #
#   DWORD Status;           # Or BYTE ErrorClass;         #
#                           #    BYTE Reserved;           #
#                           #    WORD Error;              #
#   BYTE  Flags;                                          #
#   WORD  Flags2;                                         #
#   WORD  PidHigh;          # 0 like noone know it        #
#   BYTE  Signature[8];                                   #
#   WORD  Reserved;                                       #
#   WORD  Tid;              # Tree ID                     #
#   WORD  Pid;              # Process ID                  #
#   WORD  Uid;              # User ID                     #
#   WORD  Mid;              # Multiplex ID                #
# }                                                       #
#                                                         #
#---------------------------------------------------------#

function smb_header (Command, Status, Flags, Flags2, Bsrspyl)
{
 local_var header, fl, fl2;

 if (!isnull (Flags))
   fl = Flags;
 if (!isnull (Flags2))
   fl2 = Flags2;
   
 header = '\xFFSMB';
 header += raw_byte(b:Command);
 header += Status;
 header += raw_byte (b:session_get_flags() | fl);
 header += raw_word (w:session_get_flags2() | fl2);
 header += raw_word (w:0);
 if ( Bsrspyl )
  header += 'BSRSPYL ';
 else
  header += raw_dword (d:session_get_sequencenumber()) + raw_dword (d:0);

 header += raw_word (w:0);
 header += raw_word (w:session_get_tid());
 header += raw_word (w:session_get_pid());
 header += raw_word (w:session_get_uid());
 header += raw_word (w:session_get_mid());

 return header;
}



function smb_check_success (data)
{
 local_var header, flags2, code;
 
 # Some checks in the header first
 header = get_smb_header (smbblob:data);
 if (!header)
   return FALSE;

 flags2 = get_header_flags2 (header:header);
 if (flags2 & SMB_FLAGS2_32BIT_STATUS)
 {
   code = get_header_nt_error_code (header:header);
   if (code != STATUS_SUCCESS)
     return FALSE;
 }
 else
 {
   code = get_header_dos_error_code (header:header);
   if (code != NO_ERROR)
     return FALSE;
 }

 return TRUE;
}


#-----------------------------------------------------------------#
# Encode name and service to the netbios network format           #
#-----------------------------------------------------------------#

function netbios_encode(data,service)
{
 local_var tmpdata, ret, i, o, odiv, omod, c;

 ret = "";
 tmpdata = data;

 while (strlen(tmpdata) < 15)
 {
   tmpdata += " ";
 }

 tmpdata += raw_string(service);

 for(i=0;i<16;i=i+1)
 {
   o = ord(tmpdata[i]);
   odiv = o/16;
   odiv = odiv + ord("A");
   omod = o%16;
   omod = omod + ord("A");
   c = raw_string(odiv, omod);

   ret = ret+c;
 }

 return raw_byte (b:strlen(ret)) + ret;
}


#-----------------------------------------------------------------#
# Convert a netbios name to the netbios network format            #
#-----------------------------------------------------------------#

function netbios_name(orig)
{
 return netbios_encode(data:orig, service:0x20);
}


function netbios_sendrecv (type, data)
{
 local_var req, socket, timeout, header, len, trailer;

 req = netbios_header (type:type, length:strlen(data)) +
       data;

 socket = session_get_socket();
 if (!socket) return NULL;
 timeout = session_get_timeout ();

 send (socket:socket, data:req);

 header = recv(socket:socket, length:4, min:4, timeout:timeout);
 if (strlen(header) < 4)
   return(NULL);
   
 len = 65535 * ord(header[1]) +
       256 * ord(header[2]) +
       ord(header[3]);

 if (len > 100000)
   len = 100000;

 trailer = recv(socket:socket, length:len, min:len, timeout:timeout);
 if (strlen(trailer) < len )
   return(NULL);

 return header + trailer;
}





#==================================================================#
# Section 4. Netbios Functions                                     #
#==================================================================#

function netbios_session_request ()
{
 local_var req, resp, rep, port, called_name, calling_name, name, data;

 port = kb_smb_transport ();
 if (port == 445)
   return TRUE;

 name = get_kb_item ("SMB/netbios_name");
 if (name == TRUE)
   called_name = netbios_name (orig:session_get_hostname());
 else
   called_name = netbios_name (orig:"*SMBSERVER");

 calling_name = netbios_name (orig:NULL);

 data = called_name + raw_byte (b:0) +
        calling_name + raw_byte (b:0);
 rep = netbios_sendrecv (type:0x81, data:data);
 if (!rep)
   return NULL;

 if (ord(rep[0]) != 0x82)
   return FALSE;

 return TRUE;
}



#==================================================================#
# Section 4a. CIFS Functions                                       #
#==================================================================#


#---------------------------------------------------------#
# Function    : smb_negotiate_protocol                    #
# Description : Negotiate the SMB protocol to use         #
#---------------------------------------------------------#
#                                                         #
# SMB header :                                            #
#    Command : SMB_COM_NEGOTIATE                          #
#              Status = STATUS_SUCCESS                    #
#              Flags  = SMB_FLAGS_CANONICAL_PATHNAMES |   #
#                       SMB_FLAGS_CASELESS_PATHNAMES      #
#              Flags2 = SMB_FLAGS2_UNICODE_STRINGS |      #
#                       SMB_FLAGS2_KNOWS_LONG_NAMES       #
#              PidHig = 0                                 #
#              Signature = NULL (0,0..)                   #
#              Tid    = 0                                 #
#              Uid    = 0                                 #
#              Mid    = 2                                 #
#                                                         #
# SMB parameters :                                        #
#   BYTE  WordCount;      # 0                             #
#                                                         #
# SMB data :                                              #
#   WORD ByteCount;       # Number of byte                #
#   {                                                     #
#    BYTE BufferFormat;   # 0x02 (Dialect)                #
#    BYTE Name[];         # NTLM 0.12                     #
#   }                                                     #
#   {                                                     #
#    ...                  # PC NETWORK PROGRAM 1.0        #
#                         # MICROSOFT NETWORKS 1.03       #
#                         # MICROSOFT NETWORKS 3.0        #
#                         # LANMAN1.0                     #
#                         # LM1.2X002                     #
#                         # Samba                         #
#                         # NT LANMAN 1.0                 #
#   }                     # NT LM 0.12                    #
#                                                         #
#---------------------------------------------------------#

function smb_negotiate_protocol (extended)
{
  local_var header, parameters, data, packet, ret, i, ns;

  if (isnull(extended) || (extended == TRUE))
  {
    header = smb_header (Command: SMB_COM_NEGOTIATE,
                         Status : nt_status (Status: STATUS_SUCCESS),
                         Flags2 : SMB_FLAGS2_EXTENDED_SECURITY);
  }
  else
  {
    header = smb_header (Command: SMB_COM_NEGOTIATE,
                         Status : nt_status(Status:STATUS_SUCCESS));
  }
  parameters = smb_parameters (data:NULL); # No parameters

  data = NULL;
  ns = supported_protocol;

  if (!session_smb2_support())
    ns--;

  for (i = 0; i < ns; i++)
  {
    data += raw_byte (b:0x02) + ascii (string:protocol[i]);
  }

  # Watermark for PVS to flag communications coming from Nessus
  data += raw_byte(b:0x02) + ascii(string:"Tenable Nessus");

  data = smb_data (data:data);

  packet = netbios_packet (header:header, parameters:parameters, data:data);

  return smb_sendrecv (data:packet);
}




#---------------------------------------------------------#
# Function    : smb_session_setup_andx_lanman_core        #
# Description : Create SMB packet for LANMAN2.1 setupandx #
#---------------------------------------------------------#
#                                                         #
# SMB parameters :                                        #
#   BYTE  WordCount;                                      #
#   BYTE  Command;                                        #
#   BYTE  Reserved;                                       #
#   WORD  Offset;                                         #
#   WORD  MaxBufferSize;                                  #
#   WORD  MaxMpxCount;                                    #
#   WORD  VcNumber;                                       #
#   DWORD SessionKey;                                     #
#   WORD  PasswordLength;                                 #
#   DWORD Reserved;                                       #
#                                                         #
# SMB data :                                              #
#   WORD ByteCount;                                       #
#   BYTE Password[];                                      #
#   BYTE AccountName[];                                   #
#   BYTE PrimaryDomain[];                                 #
#   BYTE NativeOS[];                                      #
#   BYTE NativeLanMan[];                                  #
#                                                         #
#---------------------------------------------------------#

function smb_session_setup_andx_lanman_core (session_key,login,domain,password,hash,mode,challenge)
{
 local_var name,dom,pass,header,parameters,data,packet,response,code,flags2,skey,guest,ret,uid,sig;
 local_var os_info, domain_info, lan_info, mult;

 
 header = smb_header (Command: SMB_COM_SESSION_SETUP_ANDX,
                      Status: nt_status (Status: STATUS_SUCCESS),
		      Bsrspyl:TRUE);

 # LANMAN2.1 names are uppercase and ascii
 name = toupper(login);
 dom = toupper (domain);
 pass = toupper (password);
 
 # If challenge/response mode we generate the response, else we keep plain text password
 if (pass && (mode & NEGOTIATE_SECURITY_CHALLENGE_RESPONSE))
 {
  response = LM_Response (password:cstring (string:pass), challenge:challenge, hash:hash);

  pass = response[0];
  skey = response[1] + response[0];
 }
 
 parameters = raw_byte (b:255) + # no further command
              raw_byte (b:0) +
              raw_word (w:0) +
              raw_word (w:session_get_buffersize()) +
              raw_word (w:1) +
              raw_word (w:0) +
              raw_dword (d:session_key) +
              raw_word (w:strlen(pass)) +
              raw_dword (d:0);
 
 parameters = smb_parameters (data:parameters);
  
 data = pass +
        cstring (string:name) +
        cstring (string:dom) +
        cstring (string:nes_native_os) +
        cstring (string:nes_native_lanman);

 data = smb_data (data:data);

 packet = netbios_packet (header:header, parameters:parameters, data:data);

 ret = smb_sendrecv (data:packet);
 if (!ret)
   return NULL;

 if (smb_check_success (data:ret) == FALSE)
   return NULL;
 
 # Some checks in the header first
 header = get_smb_header (smbblob:ret);
 if (!header)
   return NULL;

 sig = hexstr (get_header_signature (header:header));
 if ("0000000000000000" >!< sig)
 {
  # Security signatures are enabled only if server support them
  if (!session_get_mackey())
    session_set_mackey (key:skey);

  # we need to mark 2 previous exchange as signed
  session_increase_sequencenumber();
  session_increase_sequencenumber();
 }

 uid = get_header_uid (header:header);
 session_set_uid (uid:uid);

 # We now parse/take information in SMB parameters
 parameters = get_smb_parameters (smbblob:ret);
 if (!parameters || (strlen(parameters) < 6))
   return NULL;
 
 guest = get_word (blob:parameters, pos:4);
 session_set_guest (guest:guest);

 data = get_smb_data (smbblob:ret);

 os_info = get_string (blob:data, pos:0);
 if (session_is_unicode ())
   mult = 2;
 else
   mult = 1;
 lan_info = get_string (blob:data, pos: (strlen(os_info)+1)*mult);

 domain_info = NULL;

 session_set_host_info (domain:domain_info, os:os_info, lan:lan_info);

 return packet; 
}



#---------------------------------------------------------#
# Function    : smb_session_setup_andx_ntlm_core          #
# Description : Create SMB packet for NTLM setupandx      #
#---------------------------------------------------------#
#                                                         #
# SMB parameters :                                        #
#   BYTE  WordCount;                                      #
#   BYTE  Command;                                        #
#   BYTE  Reserved;                                       #
#   WORD  Offset;                                         #
#   WORD  MaxBufferSize;                                  #
#   WORD  MaxMpxCount;                                    #
#   WORD  VcNumber;                                       #
#   DWORD SessionKey;                                     #
#   WORD  CaseInsensitivePasswordLength;                  #
#   WORD  CaseSensitivePasswordLength;                    #
#   DWORD Reserved;                                       #
#   DWORD Capabilities;                                   #
#                                                         #
# SMB data :                                              #
#   WORD  ByteCount;                                      #
#   BYTE  CaseInsensitivePassword[];                      #
#   BYTE  CaseSensitivePassword[];                        #
#   BYTE  Pad;        # present with unicode only         #   
#   BYTE  AccountName[];                                  #
#   BYTE  PrimaryDomain[];                                #
#   BYTE  NativeOS[];                                     #
#   BYTE  NativeLanMan[];                                 #
#   BYTE  Pad2[];     # seems to be optionnal             #
#                                                         #
#---------------------------------------------------------#

function smb_session_setup_andx_ntlm_core (session_key,login,domain,password,lm_hash,ntlm_hash,mode,challenge,version)
{
 local_var name,dom,pass,spass,ipass,header,parameters,data,packet,response,code,flags2,skey,guest;
 local_var domain_info, os_info, lan_info, mult, ret, uid, hinfo;
 
 header = smb_header (Command: SMB_COM_SESSION_SETUP_ANDX,
                      Status: nt_status (Status: STATUS_SUCCESS),
		      Bsrspyl:TRUE);

 if (!(mode & NEGOTIATE_SECURITY_CHALLENGE_RESPONSE))
 {
  # SAMBA servers support plain text password in NTLM.
  # Implementing CIFS don't know exactly how to do with password.
  # Need to look at SAMBA code
  return NULL;
 }

 ipass = spass = NULL;

 # NTLM use only unicode password
 if (session_is_unicode() == 0)
 {
  session_set_unicode (unicode:1);
  pass = cstring (string:password, _null:1);
  name = cstring (string:login, _null:1);
  dom = cstring (string:domain, _null:1);  
  session_set_unicode (unicode:0);
 }
 else
 {
  pass = cstring (string:password, _null:1);
  name = cstring (string:login, _null:1);
  dom = cstring (string:domain, _null:1);  
 }
 
 # If challenge/response mode we generate the response, else we keep plain text password
 if ((pass || lm_hash || ntlm_hash) && (mode & NEGOTIATE_SECURITY_CHALLENGE_RESPONSE))
 {
  # NOT WORKING !
  #response= NTLMv2_Response (password:pass, login:name, domain:dom, challenge:challenge);
  #spass = response[0];
  
  if (version == 2)
  {
    response = LMv2_Response (password:pass, login:name, hash:ntlm_hash, domain:dom, challenge:challenge);
    ipass = response[0];
    # Windows allways use unicode password for mac key
    # like it is null (NTLMv2 to fix) we use a null byte [16] array
    skey = response[1];
  }
  else
  {
    if (pass || ntlm_hash)
    {
     response = NTLM_Response (password:pass, hash:ntlm_hash, challenge:challenge);
     spass = response[0];
    }
    else
    {
     response = LM_Response (password:pass, hash:lm_hash, challenge:challenge);
     ipass = response[0];
    }
    skey = response[1] + response[0];
  }

  # Security signatures are enabled only if server support them
  if (!session_get_mackey() && ((mode & NEGOTIATE_SECURITY_SIGNATURES_REQUIRED) || (mode & NEGOTIATE_SECURITY_SIGNATURES_ENABLED)))
    session_set_mackey (key:skey);

 }
 
 parameters = raw_byte (b:255) + # no further command
              raw_byte (b:0) +
              raw_word (w:0) +
              raw_word (w:session_get_buffersize()) +
              raw_word (w:1) +
              raw_word (w:0) +
              raw_dword (d:session_key) +
	      raw_word (w:strlen(ipass)) +
              raw_word (w:strlen(spass)) +
              raw_dword (d:0) +
	      raw_dword (d: CAP_UNICODE * session_is_unicode() | CAP_LARGE_FILES | CAP_NT_SMBS | CAP_STATUS32 | CAP_LEVEL_II_OPLOCKS | CAP_NT_FIND );
 
 parameters = smb_parameters (data:parameters);
 
 # If Unicode we must add 1 byte pad
 if (session_is_unicode() == 1)
   spass += raw_string(0x00);
   
 data = ipass + spass +
        cstring (string:login) +
        cstring (string:domain) +
        cstring (string:nes_native_os) +
        cstring (string:nes_native_lanman);
 
 data = smb_data (data:data);

 packet = netbios_packet (header:header, parameters:parameters, data:data);

 ret = smb_sendrecv (data:packet);
 if (!ret)
   return NULL;

 data = get_smb_data (smbblob:ret);

 if (strlen(data)%2)
   data = substr(data,1,strlen(data)-1);

 os_info = get_string (blob:data, pos:0);
 if (session_is_unicode ())
   mult = 2;
 else
   mult = 1;
 lan_info = get_string (blob:data, pos: (strlen(os_info)+1)*mult);
 domain_info = get_string (blob:data, pos: (strlen(os_info)+strlen(lan_info)+2)*mult);

 session_set_host_info (domain:domain_info, os:os_info, lan:lan_info);

 if (smb_check_success (data:ret) == FALSE)
   return NULL;

 # Some checks in the header first
 header = get_smb_header (smbblob:ret);
 if (!header)
   return NULL;

 uid = get_header_uid (header:header);
 session_set_uid (uid:uid);

 # We now parse/take information in SMB parameters
 parameters = get_smb_parameters (smbblob:ret);
 if (!parameters || (strlen(parameters) < 6))
   return NULL;
 
 guest = get_word (blob:parameters, pos:4);
 session_set_guest (guest:guest);

 return packet; 
}



#---------------------------------------------------------#
# Function    : smb_session_setup_andx_kerberos_core      #
# Description : Create SMB packet for Kerberos setupandx  #
#---------------------------------------------------------#

function smb_session_setup_andx_kerberos_core (session_key,login,password,realm,host,mode)
{
 local_var name,dom,pass,spass,ipass,header,parameters,data,packet,response;
 local_var uid, bloblength, securityblob, guest, key, kerb_data, flags2, code, ret;

 header = smb_header (Command: SMB_COM_SESSION_SETUP_ANDX,
                      Status: nt_status (Status: STATUS_SUCCESS),
		      Bsrspyl:TRUE);

 kerb_data = kerberos_securityblob (login:login,password:password,realm:realm,host:host);
 if (isnull(kerb_data))
   return NULL;
 
 securityblob = kerb_data[1];
 
 parameters = raw_byte (b:255) + # no further command
              raw_byte (b:0) +
              raw_word (w:0) +
              raw_word (w:session_get_buffersize()) +
              raw_word (w:1) +
              raw_word (w:0) +
              raw_dword (d:session_key) +
              raw_word (w:strlen(securityblob)) +
              raw_dword (d:0) +
	      raw_dword (d: CAP_UNICODE * session_is_unicode() | CAP_LARGE_FILES | CAP_NT_SMBS | CAP_STATUS32 | CAP_LEVEL_II_OPLOCKS | CAP_NT_FIND | CAP_EXTENDED_SECURITY);
 
 parameters = smb_parameters (data:parameters);
 
 # If strlen (securityblob) even add 1 pad byte
 if ((strlen (securityblob) % 2) == 0)
   securityblob += raw_string(0x00);
   
 data = securityblob + 
        cstring (string:nes_native_os) +
        cstring (string:nes_native_lanman);
 
 data = smb_data (data:data);

 packet = netbios_packet (header:header, parameters:parameters, data:data);

 ret = smb_sendrecv (data:packet);
 if (!ret)
   return NULL;
 
 # Some checks in the header first
 header = get_smb_header (smbblob:ret);
 if (!header)
   return NULL;

 flags2 = get_header_flags2 (header:header);
 if (flags2 & SMB_FLAGS2_32BIT_STATUS)
 {
   code = get_header_nt_error_code (header:header);
   if (code != STATUS_SUCCESS)
     return NULL;
 }
 else
 {
   code = get_header_dos_error_code (header:header);
   if (code != NO_ERROR)
     return NULL;
 }

 uid = get_header_uid (header:header);
 session_set_uid (uid:uid);
 
 # We now parse/take information in SMB parameters
 parameters = get_smb_parameters (smbblob:ret);
 if (!parameters || (strlen(parameters) < 8))
   return NULL;
 
 guest = get_word (blob:parameters, pos:4);
 session_set_guest (guest:guest);

 bloblength = get_word (blob:parameters, pos:6);
 
 # We now parse/take information in SMB parameters
 data = get_smb_data (smbblob:ret);
 if (!data)
   return NULL;
  
 if (strlen(data) < bloblength)
   return NULL;
 
 securityblob = substr (data, 0, bloblength - 1);
 if (!securityblob)
   return NULL;

 key = check_kerberos_response (data:securityblob, key:kerb_data[0]);
 if (isnull(key))
   return NULL;

 if (!session_get_mackey() && ((mode & NEGOTIATE_SECURITY_SIGNATURES_REQUIRED) || (mode & NEGOTIATE_SECURITY_SIGNATURES_ENABLED)) && (login))
 {
  if (key[0] == 0)
    session_set_mackey (key:kerb_data[0]);
  else
    session_set_mackey (key:key[1]);

  session_increase_sequencenumber();
  session_increase_sequencenumber();
 }

 return packet; 
}


#---------------------------------------------------------#
# Function    : smb_session_setup_andx_ntlmssp_core       #
# Description : Create SMB packet for ntlmssp setupandx   #
#---------------------------------------------------------#

function smb_session_setup_andx_ntlmssp_core (session_key,login,password,hash,domain,mode)
{
 local_var name,dom,pass,header,parameters,data,packet,response,uid,guest, bloblength, ret, code;
 local_var challenge, securityblob,securityblob_length,d_name,h_info,os_info,lan_info,mult,hinfo;
 local_var sblob, skey, i;

 header = smb_header (Command: SMB_COM_SESSION_SETUP_ANDX,
                      Status: nt_status (Status: STATUS_SUCCESS),
		      Bsrspyl:TRUE);

 securityblob = ntlmssp_negotiate_securityblob ();

 parameters = raw_byte (b:255) + # no further command
              raw_byte (b:0) +
              raw_word (w:0) +
              raw_word (w:session_get_buffersize()) +
              raw_word (w:1) +
              raw_word (w:1) +
              raw_dword (d:session_key) +
              raw_word (w:strlen(securityblob)) +
              raw_dword (d:0) +
	      raw_dword (d: CAP_UNICODE * session_is_unicode() | CAP_LARGE_FILES | CAP_NT_SMBS | CAP_STATUS32 | CAP_LEVEL_II_OPLOCKS | CAP_NT_FIND | CAP_EXTENDED_SECURITY);
 
 parameters = smb_parameters (data:parameters);
 
 # If strlen (securityblob) even add 1 pad byte
 if ((strlen (securityblob) % 2) == 0)
   securityblob += raw_string(0x00);
   
 data = securityblob + 
        cstring (string:nes_native_os) +
        cstring (string:nes_native_lanman) +
	cstring (string:domain);
 
 data = smb_data (data:data);

 packet = netbios_packet (header:header, parameters:parameters, data:data);

 ret = smb_sendrecv (data:packet); 
 if (!ret)
   return NULL;

 # Some checks in the header first
 header = get_smb_header (smbblob:ret);
 if (!header)
   return NULL;
 
 code = get_header_nt_error_code (header:header);
 if (code != STATUS_MORE_PROCESSING_REQUIRED)
   return NULL;

 uid = get_header_uid (header:header);
 session_set_uid (uid:uid);
 
 # We now parse/take information in SMB parameters
 parameters = get_smb_parameters (smbblob:ret);
 if (!parameters)
   return NULL;
 
 bloblength = get_word (blob:parameters, pos:6);
 
 # We now parse/take information in SMB parameters
 data = get_smb_data (smbblob:ret);
 if (!data)
   return NULL;
  
 if (strlen(data) < bloblength)
   return NULL;
 
 securityblob = substr (data, 0, bloblength - 1);
 challenge = ntlmssp_parse_challenge (data:securityblob);
 if (isnull(challenge))
   return NULL; 

 session_set_addrlist(addrlist:challenge[3]);
 sblob = challenge[3];

 d_name = get_string2 (blob:challenge[1], pos:0, len:strlen(challenge[1]));
 challenge = challenge[0];

 # If bloblength is even account for extra 1 pad byte
 hinfo = substr(data,bloblength,strlen(data)-1); 
 if ((strlen(hinfo) > 1) && ((bloblength % 2) == 0))
   hinfo = substr(hinfo, 1, strlen(hinfo)-1);

 os_info = get_string (blob:hinfo, pos:0);
 if (session_is_unicode ())
   mult = 2;
 else
   mult = 1;
 lan_info = get_string (blob:hinfo, pos: (strlen(os_info)+1)*mult);

 session_set_host_info (domain:d_name, os:os_info, lan:lan_info);

 if (login)
 {
  # NTLM use only unicode password
  if (session_is_unicode() == 0)
  {
   session_set_unicode (unicode:1);
   if (password)
     pass = cstring (string:password, _null:1);
   else
     pass = NULL;
   name = cstring (string:login, _null:1);
   dom = cstring (string:domain, _null:1);  
   session_set_unicode (unicode:0);
  }
  else
  {
   pass = cstring (string:password, _null:1);
   name = cstring (string:login, _null:1);
   dom = cstring (string:domain, _null:1);  
  }
 }
 else
 {
  name = NULL;
  pass = NULL;
  dom = NULL;
 }

 # generates a random key for the session
 skey = NULL;
 for (i=0 ; i<16; i++)
   skey += raw_string(rand()&0xFF);

 securityblob = ntlmssp_auth_securityblob (password:pass,login:name,hash:hash,domain:dom,challenge:challenge,skey:skey,sblob:sblob);
 if (isnull(securityblob))
   return NULL;

 # Security signatures are enabled only if server support them
 # We use null session_key as we used LMv2 only
 if (!session_get_mackey() && ((mode & NEGOTIATE_SECURITY_SIGNATURES_REQUIRED) || (mode & NEGOTIATE_SECURITY_SIGNATURES_ENABLED)) && (login))
  # session_set_mackey (key:crap(data:raw_string(0),length:16));
   session_set_mackey (key:securityblob[0]);

 securityblob = securityblob[1];

 header = smb_header (Command: SMB_COM_SESSION_SETUP_ANDX,
                      Status: nt_status (Status: STATUS_SUCCESS),
		      Bsrspyl:TRUE);

 parameters = raw_byte (b:255) + # no further command
              raw_byte (b:0) +
              raw_word (w:0) +
              raw_word (w:session_get_buffersize()) +
              raw_word (w:1) +
              raw_word (w:0) +
              raw_dword (d:session_key) +
              raw_word (w:strlen(securityblob)) +
              raw_dword (d:0) +
	      raw_dword (d: CAP_UNICODE * session_is_unicode() | CAP_LARGE_FILES | CAP_NT_SMBS | CAP_STATUS32 | CAP_LEVEL_II_OPLOCKS | CAP_NT_FIND | CAP_EXTENDED_SECURITY);
 
 parameters = smb_parameters (data:parameters);
 
 # If strlen (securityblob) even add 1 pad byte
 if ((strlen (securityblob) % 2) == 0)
   securityblob += raw_string(0x00);
   
 data = securityblob + 
        cstring (string:nes_native_os) +
        cstring (string:nes_native_lanman) +
	cstring (string:domain);
 
 data = smb_data (data:data);

 packet = netbios_packet (header:header, parameters:parameters, data:data);
 
 ret = smb_sendrecv (data:packet); 
 if (!ret)
   return NULL;

 # Some checks in the header first
 header = get_smb_header (smbblob:ret);
 if (!header)
   return NULL;
 
 code = get_header_nt_error_code (header:header);
 if (code != STATUS_SUCCESS)
   return NULL;

 uid = get_header_uid (header:header);
 session_set_uid (uid:uid);
 
 # We now parse/take information in SMB parameters
 parameters = get_smb_parameters (smbblob:ret);
 if (!parameters || (strlen(parameters) < 8))
   return NULL;

 guest = get_word (blob:parameters, pos:4);
 session_set_guest (guest:guest);

 bloblength = get_word (blob:parameters, pos:6);
 # We now parse/take information in SMB parameters
 data = get_smb_data (smbblob:ret);
 if (!data)
   return NULL;
  
 if (strlen(data) < bloblength)
   return NULL;
 
 securityblob = substr (data, 0, bloblength - 1);

 challenge = ntlmssp_parse_response (data:securityblob);
 if (isnull(challenge) || (challenge != 0)) # Accept Completed
   return NULL;

 return packet;
}




#---------------------------------------------------------#
# Function    : smb_session_setup_andx                    #
# Description : Authenticate to the remote host           #
#---------------------------------------------------------#

function smb_session_setup_andx (session_key, dialect, challenge, mode, extended, login, password, lm_hash, ntlm_hash, domain, host, realm)
{
 local_var packet, ct, onlyv2, only_kerb;
 
 # If cleartext is prohibited we return NULL
 ct = get_kb_item("SMB/dont_send_in_cleartext");
 if ((ct == "yes") && (!(mode & NEGOTIATE_SECURITY_CHALLENGE_RESPONSE))) return NULL;

 onlyv2 = get_kb_item ("SMB/dont_send_ntlmv1");
 only_kerb = get_kb_item ("SMB/only_use_kerberos");

 # If LANMAN2.1 protocol
 if (protocol[dialect] == "LANMAN2.1")
 {
  if (onlyv2) return NULL;

  packet = smb_session_setup_andx_lanman_core (session_key:session_key,
                                               login:login,
					       domain:domain,
					       password:password,
					       hash:lm_hash,
					       mode:mode,
					       challenge:challenge);
  return packet;
 }
 # If NT LM 0.12 protocol
 if (protocol[dialect] == "NT LM 0.12")
 {
  if (isnull (extended))
  {
   if (password || ntlm_hash)
     packet = smb_session_setup_andx_ntlm_core (session_key:session_key,
                                              login:login,
 	 				      domain:domain,
 					      password:password,
					      lm_hash:lm_hash,
					      ntlm_hash:ntlm_hash,
					      mode:mode,
					      challenge:challenge,
					      version:2);
   else
     packet = NULL;

   if (! packet )
   {
    if (onlyv2) return NULL;

    packet = smb_session_setup_andx_ntlm_core (session_key:session_key,
                                              login:login,
 	 				      domain:domain,
					      password:password,
					      lm_hash:lm_hash,
					      ntlm_hash:ntlm_hash,
 					      mode:mode,
					      challenge:challenge,
					      version:1);
   }
   return packet;
  }
  else
  {
   if ((extended == 2) && defined_func ("open_sock_kdc") && get_kb_item('KerberosAuth/enabled') && login && password && realm)
   {
    # If Kerberos
    packet = smb_session_setup_andx_kerberos_core (session_key:session_key,
    						   login:login,
						   password:password,
						   host:host,
						   realm:realm,
                                                   mode:mode);

    if (!isnull (packet))
      return packet;
      
    if(only_kerb) return NULL;
      
   }
   
   # If NTLMSSP or if Kerberos failed
   packet = smb_session_setup_andx_ntlmssp_core (session_key:session_key,
   						 login:login,
						 password:password,
						 hash:ntlm_hash,
						 domain:domain,
                                                 mode:mode);
   return packet;
  }
 }
}




#---------------------------------------------------------#
# Function    : smb_login                                 #
# Description : Negotiate authentication  with remote     #
#               host.                                     #
# Return      : Return 1 on success , 0 on failure        #
#---------------------------------------------------------#

function smb_login (login,password,domain,lm_hash,ntlm_hash)
{
 local_var ret, code, flags2, header, parameters, data, unicode, SecurityBlob, ServerGUID;
 local_var DialectIndex, SecurityMode, MaxBufferSize, SessionKey, Capabilities, EncryptionKeyLength, EncryptionKey, Extended;
 local_var realm,host, ext;
 local_var spnego, michlist, DomainName, next, ServerName;

 host = realm = NULL;

 #
 # First step : Protocol negotiation 
 #

 if (isnull(password) && isnull(ntlm_hash) && !isnull(lm_hash))
   ext = FALSE;
 else
   ext = TRUE;

 ret = smb_negotiate_protocol (extended:ext);
 if (!ret || (strlen(ret) < 4))
   return NULL;
 
 if (get_dword(blob:ret, pos:0) == 0x424d53fe)
   return smb2_login(negotiate:ret, login:login, password:password, domain:domain, lm_hash:lm_hash, ntlm_hash:ntlm_hash);


 # Some checks in the header first
 header = get_smb_header (smbblob:ret);
 if (!header)
   return NULL;

 flags2 = get_header_flags2 (header:header);
 if (flags2 & SMB_FLAGS2_32BIT_STATUS)
 {
  code = get_header_nt_error_code (header:header);
  if (code != STATUS_SUCCESS)
    return code;
 }
 else
 {
  code = get_header_dos_error_code (header:header);
  if (code != NO_ERROR)
    return code;
 }

 code = get_header_command_code (header:header);
 if (code != SMB_COM_NEGOTIATE)
   return ERROR_BAD_COMMAND;

 # We must get unicode or not here
 unicode = flags2 & SMB_FLAGS2_UNICODE_STRINGS;

 # We now parse/take information in SMB parameters
 parameters = get_smb_parameters (smbblob:ret);
 if (!parameters)
   return NULL;
 
 # Negotiate protocol response parameters
 # NT LM 0.12                        LANMAN2.1
 # WORD  DialectIndex;               WORD  DialectIndex;
 # BYTE  SecurityMode;               WORD  SecurityMode;
 # WORD  MaxMpxCount;                WORD  MaxBufferSize;
 # WORD  MaxNumberVCs;               WORD  MaxMpxCount;
 # DWORD MaxBufferSize;              BYTE  MaxNumberVCs;
 # DWORD MaxRawSize;                 WORD  RawMode;
 # DWORD SessionKey;                 DWORD SessionKey;
 # DWORD Capabilities;               WORD  ServerTime;
 # DWORD SystemTimeLow;              WORD  ServerDate;
 # DWORD SystemTimeHigh;             WORD  ServerTimeZone;
 # WORD  ServerTimeZone;             WORD  EncryptionKeyLength;
 # BYTE  EncryptionKeyLength;        WORD  Reserved;
 # WORD  Reserved; 

 DialectIndex = get_word (blob:parameters, pos:0);

 if (DialectIndex > (supported_protocol-1))
 {
   # Bad server's response. Because it asks for an unsupported protocol
   return NULL;
 }

 Extended = NULL;

 if (protocol[DialectIndex] == "NT LM 0.12")
 {
  SecurityMode = get_byte (blob:parameters, pos:2);
  MaxBufferSize = get_dword (blob:parameters, pos:7);
  SessionKey = get_dword (blob:parameters, pos:15);
  Capabilities = get_dword (blob:parameters, pos:19);
  EncryptionKeyLength = get_byte (blob:parameters, pos:33);
 
  if (Capabilities & CAP_UNICODE)
    session_set_unicode (unicode:1);
  else
    session_set_unicode (unicode:0);
    
  if ((SecurityMode & NEGOTIATE_SECURITY_SIGNATURES_REQUIRED) || (SecurityMode & NEGOTIATE_SECURITY_SIGNATURES_ENABLED))
    session_add_flags2 (flag:SMB_FLAGS2_SECURITY_SIGNATURE);

  if (Capabilities & CAP_EXTENDED_SECURITY)
    session_add_flags2 (flag:SMB_FLAGS2_EXTENDED_SECURITY);
 
  # We now parse/take information in SMB parameters
  data = get_smb_data (smbblob:ret);
  if (!data)
    return NULL;
 
  # Negotiate protocol response data for NTLM
  # BYTE EncryptionKey[];
  # BYTE DomainName[]; // NULL terminated
  # BYTE ServerName[]; // NULL terminated

  if (Capabilities & CAP_EXTENDED_SECURITY)
  {
   if (strlen(data) < 16)
     return NULL;
   ServerGUID = substr (data, 0, 15);
   if ((strlen (data) > 16) && (login && password))
   {
     local_var mech;
     SecurityBlob = substr (data, 16, strlen(data) - 1);
     spnego = der_parse_spnego_init (sdata:SecurityBlob);
         
     if (!isnull (spnego) && (spnego[3] != NULL) && 
      (spnego[3] != "not_defined_in_RFC4178@please_ignore") &&
      (toupper(spnego[3]) != "NONE") # samba
      )
     {
       michlist = spnego[3];
       host = ereg_replace (pattern:"(.*?)\$?@.*", string:michlist, replace:"\1");
       realm = ereg_replace (pattern:".*\$?@(.*)", string:michlist, replace:"\1");
       Extended = 2; # Kerberos
     }
     # Check if Kerberos is supported by server, if so use it for auth
     # 1.2.840.48018.1.2.2  -> Microsoft Kerberos 5
     # 1.2.840.113554.1.2.2 -> Kerberos 5
     else if(!isnull (spnego) && (spnego[0] != NULL) && '1.2.840.48018.1.2.2' >< spnego[0])
     {
       realm  = domain;
       host   =  kb_smb_name();
       if(isnull(host) || host == get_host_ip())
        host = get_host_name();
       
       Extended = 2; 
     }
     else
       Extended = 1;
   }
   else
   {
     Extended = 1; # NTLMSSP
     SecurityBlob = NULL;
   }
  }
  else
  {
   if (EncryptionKeyLength != 0)
     EncryptionKey = substr (data, 0, 7); # Allways 8 byte length
   else
     EncryptionKey = NULL;

   if (strlen(data) > 8)
     DomainName = get_string (blob:data, pos:8);
  
   next = strlen(DomainName) + null_length();
   next += strlen(EncryptionKey);
  
   if (next  < strlen(data))
     ServerName = get_string (blob:data, pos:next);
  }
 }
 
 else if (protocol[DialectIndex] == "LANMAN2.1")
 {
  #LANMAN2.1 does not support unicode
  session_set_unicode (unicode:0);
  
  SecurityMode = get_word (blob:parameters, pos:2);
  MaxBufferSize = get_word (blob:parameters, pos:4);
  SessionKey = get_dword (blob:parameters, pos:11);
  EncryptionKeyLength = get_word (blob:parameters, pos:21);
  
  # We now parse/take information in SMB parameters
  data = get_smb_data (smbblob:ret);
  if (!data)
    return NULL;
  
  # BYTE EncryptionKey[];
  if (EncryptionKeyLength != 0)
    EncryptionKey = substr (data, 0, 7); # Allways 8 byte length
  else
    EncryptionKey = NULL;
 }
 else
 {
   # Bad server's response. Because it asks for an unsupported protocol
   return NULL;
 }

 session_set_server_max_size (size:MaxBufferSize);
 if (MaxBufferSize > (session_get_buffersize() - 0x100))
 {
   if(MaxBufferSize + 0x100 > 0xffff)
    session_set_buffersize(size:0xffff);
   else 
    session_set_buffersize(size:MaxBufferSize+0x100);
 }

 if (isnull(password) && isnull(ntlm_hash) && !isnull(lm_hash))
   Extended = NULL;

 ret = smb_session_setup_andx (session_key:SessionKey, dialect:DialectIndex, challenge:EncryptionKey, mode:SecurityMode, extended:Extended, login:login, password:password, domain:domain, lm_hash:lm_hash, ntlm_hash:ntlm_hash, host:host, realm:realm);

 if (isnull (ret))
   return 0;
 else 
   return 1;
}




#---------------------------------------------------------#
# Function    : smb_tree_connect_and_x                    #
# Description : Connects to a remote share                #
#---------------------------------------------------------#

function smb_tree_connect_and_x (share)
{
 local_var header, parameters, password, path, service, data, packet, ret, tid;

 if (session_is_smb2()) return smb2_tree_connect(path:share);

 header = smb_header (Command: SMB_COM_TREE_CONNECT_ANDX,
                      Status: nt_status (Status: STATUS_SUCCESS));

 parameters = raw_byte (b:255) + # no further command
              raw_byte (b:0) +
              raw_word (w:0) +
              raw_word (w:0xC) +
              raw_word (w:1); # strlen (password)
 
 parameters = smb_parameters (data:parameters);
 
 password = raw_string (0x00); # NULL password / To change for share authentication
 path = cstring (string:"\\", _null:1) + cstring (string:session_get_hostname(), _null:1) + cstring (string:"\", _null:1) + cstring (string:share);
 service = ascii (string:"?????");
 
 data = password +
        path +
	service;
 
 data = smb_data (data:data);

 packet = netbios_packet (header:header, parameters:parameters, data:data);

 ret = smb_sendrecv (data:packet); 
 if (!ret)
   return NULL;
 
 if (smb_check_success (data:ret) == FALSE)
   return NULL;

 # Some checks in the header first
 header = get_smb_header (smbblob:ret);
 if (!header)
   return NULL;

 tid = get_header_tid (header:header);
 session_set_tid (tid:tid);

 return ret;
}


#---------------------------------------------------------#
# Function    : smb_create_and_x                          #
# Description : Connects to a remote file                 #
#---------------------------------------------------------#

function smb_create_and_x (name, desired_access, flags_attributes, share_mode, create_disposition, create_options)
{
 local_var header, parameters, data, packet, ret, offset, fid, pad, filename;

 if (session_is_smb2())
   return smb2_create(
                name:name,
                desired_access:desired_access,
                flags_attributes:flags_attributes, 
                share_mode:share_mode, 
                create_disposition:create_disposition, 
                create_options:create_options
                );

 header = smb_header (Command: SMB_COM_NT_CREATE_ANDX,
                      Status: nt_status (Status: STATUS_SUCCESS));

 pad = NULL;
 if (session_is_unicode() == 1)
   pad = raw_byte (b:0);

 filename = cstring (string:name);

 parameters = raw_byte (b:255) + # no further command
              raw_byte (b:0) +
              raw_word (w:0) +
	      raw_byte (b:0) +
              raw_word (w:strlen(cstring(string:name,_null:1))) +
	      raw_dword (d:0x16)                +  # flags to change
	      raw_dword (d:0)                   +  # root fid
	      raw_dword (d:desired_access)      +  # access mask
	      raw_dword (d:0) + raw_dword (d:0) +  # allocation size
	      raw_dword (d:flags_attributes)    +  # file attributes
	      raw_dword (d:share_mode)          +  # share access
	      raw_dword (d:create_disposition)  +  # Disposition
	      raw_dword (d:create_options)      +  # create options
	      raw_dword (d:2)                   +  # impersonation
	      raw_byte  (b:3);                     # security flags
                     	      
 parameters = smb_parameters (data:parameters);
 
 data = pad + filename;
 
 data = smb_data (data:data);

 packet = netbios_packet (header:header, parameters:parameters, data:data);

 ret = smb_sendrecv (data:packet); 
 if (!ret)
   return NULL;
 
 if (smb_check_success (data:ret) == FALSE)
   return NULL;

 parameters = get_smb_parameters (smbblob:ret);
 if (!parameters || (strlen(parameters) < 63))
   return NULL;

 offset = get_word (blob:parameters, pos:2);

 ret = NULL;
 ret[0] = get_word (blob:parameters, pos:5); # FID
 ret[1] = substr (parameters, 55, 62);       # SIZE

 return ret;
}


#---------------------------------------------------------#
# Function    : smb_write_and_x                           #
# Description : writes to a remote pipe                   #
#---------------------------------------------------------#

function smb_write_and_x (fid, offset, mode, data)
{
 local_var header, parameters, dat, packet, ret, pad;

 if (session_is_smb2()) return smb2_write(fid:fid, offset:offset, data:data);

 pad = raw_byte (b:0);

 header = smb_header (Command: SMB_COM_WRITE_ANDX,
                      Status: nt_status (Status: STATUS_SUCCESS));

 parameters = raw_byte (b:255) +            # no further command
              raw_byte (b:0) +              # reserved
              raw_word (w:0) +              # andxoffset
	      raw_word (w:fid) +            # fid
	      raw_dword (d:offset) +        # offset
              raw_dword (d:0xFFFFFFFF) +    # reserved
	      raw_word (w:mode) +           # write mode
	      raw_word (w:strlen (data)) +  # remaining
	      raw_word (w:0) +              # data length high
	      raw_word (w:strlen (data)) +  # data length low
	      raw_word (w:64) +             # data offset == 64
	      raw_dword (d:0) ;             # high offset
                    	      
 parameters = smb_parameters (data:parameters);
 
 dat = pad + data;
 
 dat = smb_data (data:dat);

 packet = netbios_packet (header:header, parameters:parameters, data:dat);

 ret = smb_sendrecv (data:packet); 
 if (!ret)
   return NULL;
 
 if (smb_check_success (data:ret) == FALSE)
   return NULL;

 return 1;
}



#---------------------------------------------------------#
# Function    : smb_read_and_x                            #
# Description : reads on a remote pipe                    #
#---------------------------------------------------------#

function smb_read_and_x (fid, offset, length)
{
 local_var header, parameters, data, packet, ret, pad, code;

 if (session_is_smb2()) return smb2_read(fid:fid, offset:offset, length:length);

 header = smb_header (Command: SMB_COM_READ_ANDX,
                      Status: nt_status (Status: STATUS_SUCCESS));

 pad = raw_byte (b:0);

 parameters = raw_byte (b:255) +            # no further command
              raw_byte (b:0) +              # reserved
              raw_word (w:0) +              # andxoffset
	      raw_word (w:fid) +            # fid
	      raw_dword (d:offset) +        # offset
	      raw_word (w:length) +         # Max count low
	      raw_word (w:length) +         # Min count
	      raw_dword (d:0xFFFFFFFF) +    # Reserved or max count high ?
	      raw_word (w:length) +         # Remaining
              raw_dword (d:0) ;             # high offset
                    	      
 parameters = smb_parameters (data:parameters);
 
 data = pad + smb_data (data:NULL);

 packet = netbios_packet (header:header, parameters:parameters, data:data);

 ret = smb_sendrecv (data:packet); 
 if (!ret)
   return NULL;
 
 header = get_smb_header (smbblob:ret);
 if (isnull (header))
   return NULL;

 code = get_header_nt_error_code(header:header);
 if ((code != STATUS_SUCCESS) && (code != STATUS_BUFFER_OVERFLOW))
   return NULL;

 if (strlen(ret) < (SMB_HDR_SIZE+14))
   return NULL;

 offset = get_word (blob:ret, pos:SMB_HDR_SIZE + 13);
 length = get_word (blob:ret, pos:SMB_HDR_SIZE + 11);
 
 if (strlen(ret) < (offset+length))
   return NULL;

 data = substr (ret, offset, offset+length-1);

 return data;
}



#---------------------------------------------------------#
# Function    : smb_trans_and_x                           #
# Description : TransAndX Request                         #
#---------------------------------------------------------#

function smb_trans_and_x (extra_parameters, transname, param, data, max_pcount, sendonly)
{
 local_var header, parameters, dat, packet, ret, pad, trans, p_offset, d_offset, plen, dlen, elen, pad2, socket;

 pad = pad2 = NULL;
 if (session_is_unicode () == 1)
   pad = raw_byte (b:0);
 else
   pad2 = raw_byte (b:0);

 header = smb_header (Command: SMB_COM_TRANSACTION,
                      Status: nt_status (Status: STATUS_SUCCESS));

 trans = cstring (string:transname);
 
 p_offset = 66 + strlen(trans) + strlen (extra_parameters);
 d_offset = p_offset + strlen (param);
 
 plen = strlen(param);
 dlen = strlen(data);
 elen = strlen(extra_parameters);

 parameters = raw_word (w:plen)            +   # total parameter count
	      raw_word (w:dlen) +   # total data count
	      raw_word (w:max_pcount)            +   # Max parameter count
	      raw_word (w:0xFFFF)         +   # Max data count
	      raw_byte (b:0)            +   # Max setup count
              raw_byte (b:0)            +   # Reserved
	      raw_word (w:0)            +   # Flags
	      raw_dword (d:0)           +   # Timeout
	      raw_word (w:0)            +   # Reserved
	      raw_word (w:plen)            +   # Parameter count
	      raw_word (w:p_offset)           +   # Parameter offset
	      raw_word (w:dlen) +   # Data count
	      raw_word (w:d_offset)           +   # Data offset
	      raw_byte (b:elen/2)            +   # Setup count
	      raw_byte (b:0);               # Reserved

 parameters += extra_parameters; 
 
 parameters = smb_parameters (data:parameters);
 
 dat = pad +
       trans +
       pad2 +
       raw_word (w:0) +
       param + 
       data;
 
 dat = smb_data (data:dat);

 packet = netbios_packet (header:header, parameters:parameters, data:dat);

 if (isnull(sendonly))
 {
  ret = smb_sendrecv (data:packet); 
  if (!ret)
    return NULL;
 
  if (smb_check_success (data:ret) == FALSE)
    return NULL;

  dat = get_smb_data (smbblob:ret);
  if (isnull (dat))
    return NULL;

  dat = substr (dat, 1, strlen(dat)-1);

  return dat;
 }
 else
 {
  socket = session_get_socket();
  if (!socket) return NULL;
 
  send (socket:socket, data:packet);
 
  if (session_get_mackey())
    session_increase_sequencenumber();
 }
}



#---------------------------------------------------------#
# Function    : smb_trans2                                #
# Description : Trans2 Request                            #
#---------------------------------------------------------#

function smb_trans2 (param, data, max_pcount, command)
{
 local_var header, parameters, dat, packet, ret, pad, trans, p_offset, d_offset, plen, dlen, elen;

 header = smb_header (Command: SMB_COM_TRANSACTION2,
                      Status: nt_status (Status: STATUS_SUCCESS));
 
 pad = raw_byte (b:0); 
 
 p_offset = 66;
 d_offset = p_offset + strlen (param);
 
 plen = strlen(param);
 dlen = strlen(data);

 parameters = raw_word (w:plen)         +   # total parameter count
	      raw_word (w:dlen)         +   # total data count
	      raw_word (w:max_pcount)   +   # Max parameter count
	      raw_word (w:1000)         +   # Max data count
	      raw_byte (b:0)            +   # Max setup count
              raw_byte (b:0)            +   # Reserved
	      raw_word (w:0)            +   # Flags
	      raw_dword (d:0)           +   # Timeout
	      raw_word (w:0)            +   # Reserved
	      raw_word (w:plen)         +   # Parameter count
	      raw_word (w:p_offset)     +   # Parameter offset
	      raw_word (w:dlen)         +   # Data count
	      raw_word (w:d_offset)     +   # Data offset
	      raw_byte (b:1)            +   # Setup count
	      raw_byte (b:0)            +   # Reserved
              raw_word (w:command);         # command

 parameters = smb_parameters (data:parameters);
 
 dat = pad +
       param + 
       data;
 
 dat = smb_data (data:dat);

 packet = netbios_packet (header:header, parameters:parameters, data:dat);

 ret = smb_sendrecv (data:packet); 
 if (!ret)
   return NULL;
 
 if (smb_check_success (data:ret) == FALSE)
   return NULL;

 dat = get_smb_data (smbblob:ret);
 if (isnull (dat))
   return NULL;

 dat = substr (dat, 1, strlen(dat)-1);

 return dat;
}


#---------------------------------------------------------#
# Function    : smb_nt_trans                              #
# Description : NT Trans Request                          #
#---------------------------------------------------------#

function smb_nt_trans (param, data, command, max_pcount, max_dcount)
{
 local_var header, parameters, dat, packet, ret, pad, trans, p_offset, d_offset, plen, dlen, elen;

 header = smb_header (Command: SMB_COM_NT_TRANSACT,
                      Status: nt_status (Status: STATUS_SUCCESS));
 
 pad = raw_byte (b:0) + raw_word(w:0); 
 
 p_offset = 76;
 d_offset = p_offset + strlen (param);
 
 plen = strlen(param);
 dlen = strlen(data);

 parameters = raw_byte (b:0)            +   # Max setup count
              raw_word (w:0)            +   # Reserved
	      raw_dword (d:plen)        +   # total parameter count
	      raw_dword (d:dlen)        +   # total data count
	      raw_dword (d:max_pcount)  +   # Max parameter count
	      raw_dword (d:max_dcount)  +   # Max data count
	      raw_dword (d:plen)        +   # Parameter count
	      raw_dword (d:p_offset)    +   # Parameter offset
	      raw_dword (d:dlen)        +   # Data count
	      raw_dword (d:d_offset)    +   # Data offset
	      raw_byte (b:0)            +   # Setup count
              raw_word (w:command);         # command

 parameters = smb_parameters (data:parameters);
 
 dat = pad +
       param + 
       data;
 
 dat = smb_data (data:dat);

 packet = netbios_packet (header:header, parameters:parameters, data:dat);

 ret = smb_sendrecv (data:packet); 
 if (!ret)
   return NULL;

 dat = get_smb_data (smbblob:ret);
 if (isnull (dat))
   return NULL;

 dat = substr (dat, 1, strlen(dat)-1);

 return dat;
}


#---------------------------------------------------------#
# Function    : smb_trans_pipe                            #
# Description : TransAndX Pipe Request                    #
#---------------------------------------------------------#

function smb_trans_pipe (fid, data, sendonly)
{
 local_var parameters, ret;

 if (session_is_smb2())
 {
  ret = smb2_ioctl(fid:fid, code:FSCTL_PIPE_TRANSCEIVE, data:data);
  if (isnull (ret))
    return NULL;

  return ret[11];
 }
 else
 {
  parameters = raw_word (w:TRANS_PIPE) +
               raw_word (w:fid);

  return smb_trans_and_x (extra_parameters:parameters, transname:"\PIPE\", param:NULL, data:data, max_pcount:0, sendonly:sendonly);
 }
}


#---------------------------------------------------------#
# Function    : smb_trans_lanman                          #
# Description : TransAndX LANMAN Request                  #
#---------------------------------------------------------#

function smb_trans_lanman (data)
{
 return smb_trans_and_x (extra_parameters:NULL, transname:"\PIPE\LANMAN", param:data, data:NULL, max_pcount:8);
}


#---------------------------------------------------------#
# Function    : smb_close                                 #
# Description : Close a pipe                              #
# Return      : 1 on success (else NULL)                  #
#---------------------------------------------------------#

function smb_close (fid)
{
 local_var header, parameters, data, packet, ret;

 if (session_is_smb2()) return smb2_close(fid:fid);

 header = smb_header (Command: SMB_COM_CLOSE,
                      Status: nt_status (Status: STATUS_SUCCESS));

 parameters = raw_word (w:fid)          +   # FID
              raw_dword (d:0xFFFFFFFF) ;    # Last write (not specified)

 parameters = smb_parameters (data:parameters);
 
 data = smb_data (data:NULL);

 packet = netbios_packet (header:header, parameters:parameters, data:data);

 ret = smb_sendrecv (data:packet); 
 if (!ret)
   return NULL;
 
 if (smb_check_success (data:ret) == FALSE)
   return NULL;

 return 1;
}


#---------------------------------------------------------#
# Function    : smb_logoff_andx                           #
# Description : Close a session                           #
# Return      : 1 on success (else NULL)                  #
#---------------------------------------------------------#

function smb_logoff_andx ()
{
 local_var header, parameters, data, packet, ret;

 if (session_is_smb2()) return smb2_logoff();

 header = smb_header (Command: SMB_COM_LOGOFF_ANDX,
                      Status: nt_status (Status: STATUS_SUCCESS));

 parameters = raw_byte (b:0xFF)         +   # No further command
              raw_byte (b:0)            +   # Reserved
              raw_word (w:0) ;              # AndXOffset

 parameters = smb_parameters (data:parameters);
 
 data = smb_data (data:NULL);

 packet = netbios_packet (header:header, parameters:parameters, data:data);

 ret = smb_sendrecv (data:packet); 
 if (!ret)
   return NULL;
 
 if (smb_check_success (data:ret) == FALSE)
   return NULL;

 return 1;
}


#---------------------------------------------------------#
# Function    : smb_tree_disconnect                       #
# Description : Close a tree                              #
# Return      : 1 on success (else NULL)                  #
#---------------------------------------------------------#

function smb_tree_disconnect ()
{
 local_var header, parameters, data, packet, ret, tid;

 tid = session_get_tid ();
 if (tid == 0)
   return 1;

 if (session_is_smb2()) return smb2_tree_disconnect();


 header = smb_header (Command: SMB_COM_TREE_DISCONNECT,
                      Status: nt_status (Status: STATUS_SUCCESS));

 parameters = smb_parameters (data:NULL);
 
 data = smb_data (data:NULL);

 packet = netbios_packet (header:header, parameters:parameters, data:data);

 ret = smb_sendrecv (data:packet); 
 if (!ret)
   return NULL;
 
 if (smb_check_success (data:ret) == FALSE)
   return NULL;

 session_set_tid (tid:0);

 return 1;
}
