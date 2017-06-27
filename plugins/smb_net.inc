#TRUSTED a2864842187c3f5b892ed7f856366ebbbcf24f04d5b1bab60b9ffb5f3c9d2167fe323a2e0d4b5d7f9ad49081a8508475481d65f2893dc3f093e72ec79e513ec04b520b2c1094e95365f514e3bfd27d41123c8d9b3d0b30be583a2bea6e38a03b9fd71657d853658ad9cb55039602b3ed4df2e431b094b044f542d3dbd064878944a5f72561b6739d7b02ac477e07b31799010da948d47e0f182205e564051ac97d097b0891c49f0c07d15f21f7ccde66cd822dab55004bfa2870d862aa9e3cbcfc5435c6370fc17769698c7ce729683fae918268330a8c91c700edefaebc2b354cfea359c26a10dae7144624331cfb5998d789e322624dd3eec1f21a98edf85405dfff148516c7cd1993e51b944eeb6ab62fdc8b9659907e72f453fca38901c6b50ba9aefa9bcf3a56d31d5e9b0add0ba24e62e89bf4dac2a47680bacc60d46953f3dde5064b34c0aefd9bcb3873844e3d386318806ac249e26ce6ec4e140fababcce974fdf3b92cc64ca545fb79757dc7811c4161c169d91fa7a7cf1ef991fd33495285d490647f5b92e10c483e4677b44e85d04ed540203af47c8480a0468a2f20b00c8e34ea82abb3a115b13e45730be4b6d89527610cb713a29042f917e6f928583d4a4a556e757a48da462eb82f77cd1bff8b58d0c3f0970407308020034fcd8b5730edca848171bace9216cfe6323112918e27a27a1ca69893ab1c8a1e
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
# smb_net.inc 
# Revision: 1.16
#

#==================================================================#
# Section 6b. Network Management API                               #
#==================================================================#



function NetGetInfo (pipe, uuid, vers, level, opnum)
{
 local_var fid, data, rep, resp, info_level, info_struct, ret;

 fid = bind_pipe (pipe:pipe, uuid:uuid, vers:vers);
 if(isnull(fid)) return NULL;

 data = class_parameter (ref_id:0x00020000, name:"\\" + session_get_hostname ()) +

	raw_dword (d:level) ;      # Info level

 data = dce_rpc_pipe_request (fid:fid, code:opnum, data:data);
 if (!data)
 {
   smb_close (fid:fid);
   return NULL;
 }

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen (rep) < 8))
 {
  smb_close (fid:fid);
  return NULL;
 }
 
 info_level = get_dword (blob:rep, pos:0);
 info_struct = substr (rep, 4, strlen(rep) - 5);

 resp = get_dword (blob:rep, pos:strlen(rep) - 4);
 if (resp != STATUS_SUCCESS)
 {
  smb_close (fid:fid);
  return NULL;
 }

 ret = NULL;
 ret[0] = info_level;
 ret[1] = info_struct;

 smb_close (fid:fid);
 
 return ret;
}



function NetEnum (pipe, level, uuid, vers, opnum)
{
 local_var fid, name, len, data, rep, resp, ret;

 fid = bind_pipe (pipe:pipe, uuid:uuid, vers:vers);
 if(isnull(fid)) return NULL;

 data = class_parameter (ref_id:0x00020000, name:"\"+session_get_hostname()) +

	raw_dword (d:level)      + # Info level
        
        # share info container
        raw_dword (d:level)      + # Share Info level (multi share request with different level ?)
        raw_dword (d:0x00020004) + # Referent ID
        raw_dword (d:0)          + # number of entries
        raw_dword (d:0)          + # share info array (NULL)

        raw_dword (d:0xFFFFFFFF) + # preferred length
        
        # Enum handle
        buffer_parameter (ref_id:0x00020008, size:0);

 data = dce_rpc_pipe_request (fid:fid, code:opnum, data:data);
 if (!data)
 {
   smb_close (fid:fid);
   return NULL;
 }

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen (rep) < 24))
 {
  smb_close (fid:fid);
  return NULL;
 }

 resp = get_dword (blob:rep, pos:strlen(rep) - 4);
 if (resp != STATUS_SUCCESS)
 {
  smb_close (fid:fid);
  return NULL;
 }

 ret = substr (rep, 0, strlen(rep)-4-1);

 smb_close (fid:fid);
 
 return ret;
}




#---------------------------------------------------------#
# Function    : NetUseAdd                                 #
# Description : Connects to the remote share.             #
#               If no share is specified authenticates    #
#               for future use (anonymous if no login)    #
# Return      : Return 1 on success                       #
#                     -1 if login failed                  #
#                      0 if share connection failed       #
#---------------------------------------------------------#

function direct_NetUseAdd (login,password,domain,share,lm_hash,ntlm_hash)
{
 local_var ret, p_type;
 local_var pref;

 p_type = get_kb_item("SMB/password_type");

 if (password &&  p_type > 0)
 {
  if (password == get_kb_item("SMB/password"))
  {
   if (p_type == 1)
   {
    lm_hash = hex2raw2(s:tolower(password));
    ntlm_hash = password = NULL;
   }
   else
   {
    ntlm_hash = hex2raw2(s:tolower(password));
    lm_hash = password = NULL;
   }
  }
 }

 if (!session_is_authenticated ())
 {
  if (netbios_session_request () != TRUE)
   return -1;

  if (smb_login (login:login, password:password, domain:domain, lm_hash:lm_hash, ntlm_hash:ntlm_hash) != 1)
    return -1;
  else
    session_set_authenticated();
 }
 
 if (!isnull (share))
 {
  #
  # Allow a user to rename the C$ to something else,
  # depending on their environment. Use with care.
  #
  if ( share == "C$" )
  {
   pref = get_preference("smb_c_share");
   if ( strlen(pref) > 0 )
   {
    ret = smb_tree_connect_and_x (share:pref);
    if ( ret ) return 1;
   }
  }
  ret = smb_tree_connect_and_x (share:share);
  if (!ret)
    return 0;
 }

 return 1;
}



#---------------------------------------------------------#
# Function    : NetUseDel                                 #
# Description : Delete connection to the remote share.    #
# Optional    : close. If close == TRUE or not specified  #
#                      logoff and close socket            # 
#---------------------------------------------------------#

function direct_NetUseDel (close)
{
 local_var soc;

 if (smb_tree_disconnect () != 1)
 {
   # smb_tree_disconnect() failed - close the socket anyways
   if ( isnull(close) || ( close == TRUE ) )
   {
     soc = session_get_socket();
     if(soc) close(soc);
   }
   return -1;
 }

 if (isnull(close) || (close == TRUE))
 {
   if (session_is_authenticated ())
   {
    smb_logoff_andx ();
   }
   soc = session_get_socket();
   if(soc) close(soc);
 }

 return 1;
}

function msrpc_unmarshal_ustring(blob, pos)
{
  local_var actual_count, blen, ret, ustr;

  blen = strlen(blob);
  
  # 4-byte alignment 
  if(pos % 4) pos += (4 - pos % 4);

  if(pos + 12 > blen) return NULL;

  actual_count = get_dword (blob:blob, pos: pos + 8) * 2; 
  if (pos +  12 + actual_count > blen)
    return NULL;
  
  # C706 says string must be NULL-terminated
  if(actual_count == 2) 
    ustr = '';
  else
    ustr = get_string2 (blob:blob, pos:pos+12, len:actual_count, _type:UNICODE_STRING);
  pos += 12 + actual_count;

  ret = NULL;
  ret['ustr'] = ustr;
  ret['next'] = pos;

  return ret;

}

#-----------------------------------------------------------#
# Function    : NetServerGetInfo                            #
# Description : Return host information                     #
# Return      : array of level info                         #
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
#-----------------------------------------------------------#

function direct_NetServerGetInfo (level)
{
  local_var actual_count, ret, rep, ref_id, pos;
  local_var announce, anndelta, comment, disc, hidden, hostname, licenses;
  local_var major, minor, platform_id, type, users, userpath; 

  # Check level
  if ((level != 100) && (level != 101) && (level != 102))
   return NULL;

  ret = NetGetInfo (pipe:"srvsvc", uuid:"4b324fc8-1670-01d3-1278-5a47bf6ee188", vers:3, level:level, opnum:OPNUM_SERVERGETINFO);

  if(isnull(ret)) return NULL;
  rep = ret[1];

  if (strlen(rep) < 24)
   return NULL;

  pos = 0;
  pos += 4; # skip ref_id for the struct
  platform_id = get_dword (blob:rep, pos: pos); pos += 4;

  pos += 4; # skip ref_id for hostname
  if (level >= 101)
  {
    if(pos + 16 > strlen(rep))
      return NULL;
    major = get_dword (blob:rep, pos: pos); pos += 4;
    minor = get_dword (blob:rep, pos: pos); pos += 4;
    type  = get_dword (blob:rep, pos: pos); pos += 4;
    pos += 4; # skip ref_id for comment 
  }
  if (level == 102)
  {
    if(pos + 28 > strlen(rep))
      return NULL; 
    users   = get_dword (blob:rep, pos: pos); pos += 4;
    disc    = get_dword (blob:rep, pos: pos); pos += 4;
    hidden  = get_dword (blob:rep, pos: pos); pos += 4;
    announce = get_dword (blob:rep, pos: pos); pos += 4;
    anndelta = get_dword (blob:rep, pos: pos); pos += 4;
    licenses = get_dword (blob:rep, pos: pos); pos += 4;
    
    pos += 4; # skip ref_id for userpath 
  }

  # Get hostname
  ret = msrpc_unmarshal_ustring(blob: rep, pos: pos);
  if(isnull(ret)) return NULL; 
  hostname = ret['ustr'];
  pos = ret['next'];
 
  # Get comment 
  if(level >= 101)
  {
    ret = msrpc_unmarshal_ustring(blob: rep, pos: pos);
    if(isnull(ret)) return NULL; 
    comment = ret['ustr'];
    pos = ret['next'];
  } 

  # Get userpath
  if(level == 102)
  {
    ret = msrpc_unmarshal_ustring(blob: rep, pos: pos);
    if(isnull(ret)) return NULL; 
    userpath = ret['ustr'];
    pos = ret['next'];
  } 

  ret = NULL;
  ret[0] = platform_id;
  ret[1] = hostname;
  if(level >= 101)
  {
    ret[2] = major;
    ret[3] = minor;
    ret[4] = type;
    ret[5] = comment;
  }
  if (level == 102)
  {
    ret[6]  = users;
    ret[7]  = disc;
    ret[8]  = hidden;
    ret[9]  = announce;
    ret[10] = anndelta;
    ret[11] = licenses;
    ret[12] = userpath;
  }

  return ret;
}



#---------------------------------------------------------#
# Function    : NetWkstaGetInfo                           #
# Description : Return workstation information            #
# Return      : array of level info                       #
#               [0] = platform_id (DWORD)                 #
#               [1] = hostname (STRING)                   #
#               [2] = domainname (STRING)                 #
#               [3] = major (DWORD)                       #
#               [4] = minor (DWORD)                       #
#               [5] = lanroot (STRING) - level 101-102    #
#               [6] = logged users (DWORD) - level 102    #
#---------------------------------------------------------#

function direct_NetWkstaGetInfo (level)
{
 local_var ret, ref_id, rep, platform_id, major, minor, pos, logged, hostname, domainname, lanrootname, actual_count;

 ret = NetGetInfo(pipe:"wkssvc", uuid:"6bffd098-a112-3610-9833-46c3f87e345a", vers:1, level:level, opnum:OPNUM_WKSTAGETINFO);
 if (isnull(ret))
   return NULL;

 level = ret[0];
 rep = ret[1];

 if ((level != 100) && (level != 101) && (level != 102))
   return NULL;

 if (strlen(rep) < 24)
   return NULL;

 ref_id = get_dword (blob:rep, pos:0);
 platform_id = get_dword (blob:rep, pos:4);
 # server_id = get_dword (blob:rep, pos:8);
 # host_id = get_dword (blob:rep, pos:12);
 major = get_dword (blob:rep, pos:16);
 minor = get_dword (blob:rep, pos:20);
 pos = 24;
 if (level >= 101)
 {
  # lan_id = get_dword (blob:rep, pos:pos);
  pos += 4;
 }
 if (level == 102)
 {
  if (strlen(rep) < 36)
    return NULL;
  logged = get_dword (blob:rep, pos:pos);
  pos += 4;
 }

 # Wksta is unicode

 # hostname
 if (strlen(rep) < pos + 12 + 4)
   return NULL;
 actual_count = get_dword(blob:rep, pos:pos+8) * 2;
 if (strlen(rep) < pos + actual_count + 4)
   return NULL;
 hostname = get_string2 (blob:rep, pos:pos+12, len:actual_count, _type:UNICODE_STRING);
 pos += actual_count + 12;
 if (actual_count%4)
   pos += 2;

 # Domain name
 if (strlen(rep) < pos + 12 + 4)
   return NULL;
 actual_count = get_dword(blob:rep, pos:pos+8) * 2;
 if (strlen(rep) < pos + actual_count + 4)
   return NULL;
 domainname = get_string2 (blob:rep, pos:pos+12, len:actual_count, _type:UNICODE_STRING);
 pos += actual_count + 12;
 if (actual_count%4)
   pos += 2;

 if (level >= 101)
 {
  # Lan root
  if (strlen(rep) < pos + 12 + 4)
    return NULL;
  actual_count = get_dword(blob:rep, pos:pos+8) * 2;
  if (strlen(rep) < pos + actual_count + 4)
    return NULL;
  lanrootname = get_string2 (blob:rep, pos:pos+12, len:actual_count, _type:UNICODE_STRING);
  pos += actual_count + 12;
  if (actual_count%4)
    pos += 2;
 }

 ret = NULL;
 ret[0] = platform_id;
 ret[1] = hostname;
 ret[2] = domainname;
 ret[3] = major;
 ret[4] = minor;
 if (level >= 101)
   ret[5] = lanrootname;
 if (level == 102)
   ret[6] = logged;

 return ret;
}


#---------------------------------------------------------#
# Function    : NetSessionEnum                            #
# Description : Return session information                #
#---------------------------------------------------------#

function direct_NetSessionEnum (level, computer, user)
{
 local_var fid, name, len, data, rep, resp, ret, comp, _user;
 local_var entries, i, lev, sess_list,  max_count, pos, sess_info, tlist;
 local_var cname, username, cltype_name, total_entries, transport;
  
 if (!isnull(computer))
  comp = class_parameter (ref_id:0x00020004, name:computer);
 else
  comp = raw_dword (d:0);

 if (!isnull(user))
  _user = class_parameter (ref_id:0x00020008, name:user);
 else
  _user = raw_dword (d:0);

 if(level != 0 && level !=1 && level != 2 && level != 10 && level != 502)
  return NULL;   

 fid = bind_pipe (pipe:"srvsvc", uuid:"4b324fc8-1670-01d3-1278-5a47bf6ee188", vers:3);

 if(isnull(fid)) return NULL; 

 data = class_parameter (ref_id:0x00020000, name:"\"+session_get_hostname()) +
        comp                     + # computer name
        _user                    + # user name
	raw_dword (d:level)      + # Info level
        
        # share info container
        raw_dword (d:level)      + # Share Info level (multi share request with different level ?)
        raw_dword (d:0x00020004) + # Referent ID
        raw_dword (d:0)          + # number of entries
        raw_dword (d:0)          + # share info array (NULL)

        raw_dword (d:0xFFFFFFFF) + # preferred length
        
        # Enum handle
        buffer_parameter (ref_id:0x00020008, size:0);

 data = dce_rpc_pipe_request (fid:fid, code:OPNUM_NETSESSENUM, data:data);
 if (!data)
 {
   smb_close (fid:fid);
   return NULL;
 }

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen (rep) < 24))
 {
  smb_close (fid:fid);
  return NULL;
 }

 resp = get_dword (blob:rep, pos:strlen(rep) - 4);
 if (resp != STATUS_SUCCESS)
 {
  smb_close (fid:fid);
  return NULL;
 }

 data = substr (rep, 0, strlen(rep)-4-1);

 smb_close (fid:fid);

 # Parse return data
 pos = 0;
 lev = get_dword (blob:data, pos:pos); pos += 4;

 if(lev != level) return NULL;
 pos +=4; # Skip switch_is(level);
 pos += 4; # Skip ref_id for SESSION_INFO_XXX_CONTAINER

 # Number of entires read
 entries = get_dword (blob:data, pos:pos); pos += 4;

 pos += 4; # Skip ref_id for SESSION_INFO_XXX

 max_count = get_dword (blob:data, pos:pos); pos += 4;
 if(max_count != entries) return NULL;

  for (i = 0; i < entries; i++)
  {
    pos += 4; # Skip ref_id for cname

    # levels 1, 2, 10, 502
    if(level > 0)
    {
      pos += 4; # Skip ref_id for username 
      sess_info[2] =  get_dword (blob:data, pos:pos); pos += 4;
      sess_info[3] =  get_dword (blob:data, pos:pos); pos += 4;

      # levels 1, 2, 502
      if(level != 10)
      {    
        sess_info[4] =  get_dword (blob:data, pos:pos); pos += 4;
        sess_info[5] =  get_dword (blob:data, pos:pos); pos += 4;

        # levels 2, 502
        if(level != 1)
        {
          pos += 4; # Skip ref_id for cltype_name  
          if(level == 502)
            pos += 4; # Skip ref_id for transport   
        }
      }
    }
    sess_list[i] = sess_info;
  }

  for (i = 0; i < entries; i++)
  {
    sess_info = sess_list[i];

    # cname
    ret = msrpc_unmarshal_ustring(blob: data, pos: pos); 
    if(isnull(ret)) return NULL;
    cname = ret['ustr'];
    pos = ret['next'];
    sess_info[0] = cname;
    
    # levels 1, 2, 10, 502
    if(level > 0)
    {
      # username
      ret = msrpc_unmarshal_ustring(blob: data, pos: pos); 
      if(isnull(ret)) return NULL;
      username = ret['ustr'];
      pos = ret['next'];
      sess_info[1] = username;

      if(level == 2 || level == 502)
      {
        # cltype_name  
        ret = msrpc_unmarshal_ustring(blob: data, pos: pos); 
        if(isnull(ret)) return NULL;
        cltype_name = ret['ustr'];
        pos = ret['next'];
        sess_info[6] = cltype_name;
    
        if(level == 502)
        {
          # transport  
          ret = msrpc_unmarshal_ustring(blob: data, pos: pos); 
          if(isnull(ret)) return NULL;
          transport = ret['ustr'];
          pos = ret['next'];
          sess_info[7] = transport;
        }
      }
    }
      
    sess_list[i] = sess_info;
  }

  # Total entries available
  if(pos % 4) pos += (4 - pos % 4);
  total_entries = get_dword (blob:data, pos:pos); pos += 4;
 
  # Currently doesn't support resumption 
  #if(entries < total_entries) 
  #{
  #  # Enum again with resumption handle
  #}
  
 return sess_list;
}


#---------------------------------------------------------#
# Function    : NetShareEnum                              #
# Description : Return host's shares information          #
# level       : SHARE_INFO_x (x = 0, 1, 2, 502)           #
#---------------------------------------------------------#

function direct_NetShareEnum (level)
{
 local_var rep, info_level, ref_id, num, max_count, actual_count, name, pos, shares, i, offset, comment;
 local_var curr_share, name_ref_id, comment_ref_id, path_ref_id, pw_ref_id, sd_ref_id, share_strings, data_offset, str;

 rep = NetEnum (pipe:"srvsvc", uuid:"4b324fc8-1670-01d3-1278-5a47bf6ee188", vers:3, level:level, opnum:OPNUM_SHAREENUM);
 if (!rep || (strlen (rep) < 24))
   return NULL;
 shares = NULL;

 info_level = get_dword (blob:rep, pos:0);
 
 if (info_level == SHARE_INFO_0)
 {
  info_level = get_dword (blob:rep, pos:4);
  ref_id = get_dword (blob:rep, pos:8);
  num = get_dword (blob:rep, pos:12);

  #SHARE_INFO_0 Array
  ref_id = get_dword (blob:rep, pos:16);
  max_count = get_dword (blob:rep, pos:20);

  # don't parse each share ref_id
  pos = 24 + max_count*4;

  for (i = 0; i<num; i++)
  {
   if (strlen (rep) < pos + 12)
     return NULL;

   max_count = get_dword (blob:rep, pos:pos);
   offset = get_dword (blob:rep, pos:pos+4);
   actual_count = get_dword (blob:rep, pos:pos+8);
  
   if (session_is_unicode () == 1)
     actual_count = actual_count * 2;

   if (strlen (rep) < pos + 12 + actual_count)
     return NULL;

   name = get_string2 (blob:rep, pos:pos + 12, len:actual_count);
  
   pos += actual_count + 12;

   while ((actual_count % 4) != 0)
   {
    actual_count ++;
    pos ++;
   }

   shares[i] = name;
  }
 }
 else if (info_level == SHARE_INFO_1)
 {
  info_level = get_dword (blob:rep, pos:4);
  ref_id = get_dword (blob:rep, pos:8);
  num = get_dword (blob:rep, pos:12);

  #SHARE_INFO_1 Array
  ref_id = get_dword (blob:rep, pos:16);
  max_count = get_dword (blob:rep, pos:20);

  # don't parse each share ref_id
  pos = 24 + max_count*(4*3);

  for (i = 0; i<num; i++)
  {
   if (strlen (rep) < pos + 12)
     return NULL;

   max_count = get_dword (blob:rep, pos:pos);
   offset = get_dword (blob:rep, pos:pos+4);
   actual_count = get_dword (blob:rep, pos:pos+8);
  
   if (session_is_unicode () == 1)
     actual_count = actual_count * 2;

   if (strlen (rep) < pos + 12 + actual_count)
     return NULL;

   name = get_string2 (blob:rep, pos:pos + 12, len:actual_count);
  
   pos += actual_count + 12;
   while ((actual_count % 4) != 0)
   {
    actual_count ++;
    pos ++;
   }

   actual_count = get_dword (blob:rep, pos:pos);
   if (session_is_unicode () == 1)
     actual_count = actual_count * 2;
   pos += actual_count + 12;

   while ((actual_count % 4) != 0)
   {
    actual_count ++;
    pos ++;
   }

   shares[i] = name;
  }
 }
 else if (info_level == SHARE_INFO_502)
 {
  # SHARE_INFO_502 structure
  # http://msdn.microsoft.com/en-us/library/windows/desktop/bb525410(v=vs.85).aspx

  info_level = get_dword (blob:rep, pos:4);
  ref_id = get_dword (blob:rep, pos:8);
  num = get_dword (blob:rep, pos:12);

  #SHARE_INFO_502 Array
  ref_id = get_dword (blob:rep, pos:16);
  max_count = get_dword (blob:rep, pos:20);

  pos = 24;
  data_offset = pos + max_count * 4 * 10;

  for (i = 0; i<num; i++)
  {
   if (strlen (rep) < pos + 40)
     return NULL;

   curr_share = make_list();
   name_ref_id = get_dword (blob:rep, pos:pos);
   curr_share[0] = NULL;
   curr_share[1] = get_dword (blob:rep, pos:pos+4);     # type
   comment_ref_id = get_dword (blob:rep, pos:pos+8);    # remark  
   curr_share[2] = NULL; 
   curr_share[3] = get_dword (blob:rep, pos:pos+12);    # permissions
   curr_share[4] = get_dword (blob:rep, pos:pos+16);    # max_uses
   curr_share[5] = get_dword (blob:rep, pos:pos+20);    # current_uses
   path_ref_id = get_dword (blob:rep, pos:pos+24);      # path
   curr_share[6] = NULL;
   pw_ref_id = get_dword (blob:rep, pos:pos+28);        # passwd
   curr_share[7] = NULL;
   curr_share[8] = get_dword (blob:rep, pos:pos+32);    # reserved
   sd_ref_id = get_dword (blob:rep, pos:pos+36);        # security_descriptor
   curr_share[9] = NULL;
   pos += 40;

   share_strings = make_list();

   if (name_ref_id != 0)
     share_strings = make_list(share_strings, 0);
   else
     continue;

   if (comment_ref_id != 0)
     share_strings = make_list(share_strings, 2);
   if (path_ref_id != 0)
     share_strings = make_list(share_strings, 6);
   if (pw_ref_id != 0)
     share_strings = make_list(share_strings, 7);
   if (sd_ref_id != 0)
     share_strings = make_list(share_strings, 9);

   if (max_index(share_strings) == 0)
     continue;

   foreach str (share_strings)
   {
     if (str == 9)  # security_descriptor
     {
       actual_count = get_dword (blob:rep, pos:data_offset);
       data_offset += 4;
     }
     else
     {
       max_count = get_dword (blob:rep, pos:data_offset);
       offset = get_dword (blob:rep, pos:data_offset+4);
       actual_count = get_dword (blob:rep, pos:data_offset+8);

       # All string fields are of WCHAR in SHARE_INFO_502_I
       actual_count = actual_count * 2; 
       data_offset += 12;
     }
  
     if (strlen (rep) < data_offset + actual_count)
       return NULL;
  
     if (str == 9) # security_descriptor
       curr_share[str] = substr(rep, data_offset, data_offset + actual_count - 1);
     else
     {
       # MSRPC strings are NULL-terminated
       if(actual_count == 2)
        curr_share[str] ='';
       else
        curr_share[str] = get_string2(blob:rep, pos:data_offset, len:actual_count, _type:UNICODE_STRING);
     }
     data_offset += actual_count;
     while ((actual_count % 4) != 0)
     {
      actual_count ++;
      data_offset ++;
     }
   }

   if (isnull(shares))
     shares = make_list();
    
   # Parse SD
   if(curr_share[9])
    curr_share[9] =  parse_security_descriptor(blob:curr_share[9]);

   shares[max_index(shares)] = curr_share;
  }
 }

 return shares;
}



#---------------------------------------------------------#
# Function    : NetWkstaUserEnum                          #
# Description : Return logged users                       #
# level       : WKSTA_USER_INFO_x (x = 0, 1)              #
#---------------------------------------------------------#

function direct_NetWkstaUserEnum (level)
{
  local_var data, entries, i, lev, max_count, ret, pos;
  local_var username, logon_domain, oth_domains, logon_server; 
  local_var user_info, user_list, total_entries;
  

  data = NetEnum (pipe:"wkssvc", uuid:"6bffd098-a112-3610-9833-46c3f87e345a", vers:1, level:level, opnum:OPNUM_WKSTAUSERENUM);

  if(isnull(data)) return NULL;
 

  pos = 0;
  lev =  get_word (blob:data, pos:pos); pos += 4;

  if(lev != level)  return NULL;

  pos += 4; # skip switch_is(level)
  pos += 4; # skip ref_id for ptr to WKSTA_USER_INFO_X_CONTAINER 

  # Number of entries returned 
  entries =  get_word (blob:data, pos:pos); pos += 4;

  pos += 4; # skip ref_id for ptr to WKSTA_USER_INFO_X  

  max_count =  get_word (blob:data, pos:pos); pos += 4;
  if(max_count != entries) return NULL; 

  pos += (4 * entries); # skip ref_ids for ptr to username
  if(level == 1)
  {
    pos += (12 * entries); # skip ref_ids for ptr to logon_domain, oth_domains, logon_server; 
  }

  for (i = 0; i < entries; i++)
  {
    # username 
    ret = msrpc_unmarshal_ustring(blob: data, pos: pos); 
    if(isnull(ret)) return NULL;
    username = ret['ustr'];
    pos = ret['next'];
    user_info[0] = username;
    
    if(level == 1)
    {
      # logon_domain 
      ret = msrpc_unmarshal_ustring(blob: data, pos: pos); 
      if(isnull(ret)) return NULL;
      logon_domain = ret['ustr'];
      pos = ret['next'];
      user_info[1] = logon_domain;

      # oth_domains  
      ret = msrpc_unmarshal_ustring(blob: data, pos: pos); 
      if(isnull(ret)) return NULL;
      oth_domains = ret['ustr'];
      pos = ret['next'];
      user_info[2] = oth_domains;
    
      # logon_server  
      ret = msrpc_unmarshal_ustring(blob: data, pos: pos); 
      if(isnull(ret)) return NULL;
      logon_server = ret['ustr'];
      pos = ret['next'];
      user_info[3] = logon_server;
    }
      
    user_list[i] = user_info;
  }

  # Total entries available
  if(pos % 4) pos += (4 - pos % 4);
  total_entries = get_dword (blob:data, pos:pos); pos += 4;
 
  # Currently doesn't support resumption 
  #if(entries < total_entries) 
  #{
  #  # Enum again with resumption handle
  #}
  
  return user_list;
  
}



#---------------------------------------------------------#
# Function    : NetServerEnum                             #
# Description : Return enumerated systems                 #
# Return      : return Array                              #
#---------------------------------------------------------#
#                                                         #
# If level == 0, array  of server names                   #
#                                                         #
# If level == 1, array of                                 #
#                  - [0] name (STRING)                    #
#                  - [1] version_major (DWORD)            #
#                  - [2] version_minor (DWORD)            #
#                  - [3] type (DWORD)                     #
#                  - [4] comment (STRING)                 #
#                                                         #
#---------------------------------------------------------#

function direct_NetServerEnum (level)
{
 local_var data, resp, convert, count, available, ret, i, offset, comment;
 local_var entry, info, j, name, tmp;

 data = raw_word (w:104)         + # Function code
        ascii (string:"WrLehDO") + # Parameter Descriptor
	ascii (string:"B16BBDz") + # Return Descriptor
	raw_word (w:level)       + # Detail level
	raw_word (w:0xFFFF)      + # Receive buffer length
	raw_dword (d:3) ;          # Server type (server + workstation)

 data = smb_trans_lanman (data:data);
 if (!data || (strlen(data) < 8))
   return NULL;
 # WORD status
 # WORD convert
 # WORD Entry count
 # WORD Available entries

 resp = get_word (blob:data, pos:0);
 convert = get_word (blob:data, pos:2);
 count = get_word (blob:data, pos:4);
 available = get_word (blob:data, pos:6);

 if (resp != STATUS_SUCCESS)
   return NULL;

 if (level == 0)
 {
  # struct :
  # byte [16] server_name;

  if (strlen (data) < (8 + count*16))
    return NULL;
  ret = NULL;
  for (i=0; i<count; i++)
  {
   ret[i] = get_string (blob:data, pos:8+i*16, _type:ASCII_STRING);
  }
 }
 else
 {
  # struct :
  # byte [16] server name
  # byte os_vers_major
  # byte os_vers_minor
  # DWORD server_type
  # DWORD comment_offset

  if (strlen (data) < (8 + count*26))
    return NULL;
  ret = NULL;
  for (i=0; i<count; i++)
  {
   # offset is a negative position at the end of the buffer
   offset = 65535 - get_dword (blob:data, pos:8+i*26+22);
   offset = strlen(data) - offset;
   if ((offset > 0) && (offset < strlen(data)))
     comment = get_string (blob:data, pos:offset, _type:ASCII_STRING);
   else
     comment = "";

   #ret[i] = substr (data, 8+i*26, 8+i*26+25) + comment;

   # NetServerInfo1 at 
   # http://msdn.microsoft.com/en-us/library/cc240225.aspx
   info = substr (data, 8+i*26, 8+i*26+25);
   tmp = substr(info, 0, 15); # 16-byte NETBIOS name; NULL-padded 
   name = NULL;
   for (j = 0; j < strlen(tmp); j++)
   {
    if(tmp[j] == '\x00')
      break;
    name += tmp[j];
   }
      
   entry[0] = name;                           # ServerName 
   entry[1] = ord(info[16]);                  # OS major version
   entry[2] = ord(info[17]);                  # OS minor version
   entry[3] = get_dword(blob: info, pos: 18); # ServerType 
   entry[4] = comment;
  
   ret[i] = entry;
  }  
 }

 return ret;
}


#---------------------------------------------------------#
# Function    : NetUserGetGroups                          #
# Description : Return user's group                       #
#---------------------------------------------------------#

function direct_NetUserGetGroups (user, resolv)
{
 local_var ret, handle, domains, sid, handle2, rid, uhandle, rids;

 ret = NULL;

 handle = SamConnect2 ();
 if (!isnull(handle))
 {
  domains = SamEnumerateDomainsInSamServer (handle:handle);
  if (!isnull(domains))
  {
   sid = SamLookupDomainInSamServer (handle:handle, domain:domains[0]);
   if (!isnull(sid))
   {
    handle2 = SamOpenDomain (handle:handle, sid:sid, access:0x200);
    if (!isnull (handle2))
    {
     rid = SamLookupNamesInDomain (handle:handle2, user:user);
     if (!isnull(rid))
     {
      uhandle = SamOpenUser (handle:handle2, rid:rid, access:0x100);
      if (!isnull(uhandle))
      {
       rids = SamGetGroupsForUser (handle:uhandle);
       if (!isnull (rids))
       {
        if (resolv)
          ret = SamLookupIdsInDomain (handle:handle2, ids:rids);
        else
          ret = rids;
       }
       SamCloseHandle(handle:uhandle);
      }
     }
    }

    SamCloseHandle(handle:handle2);
   }
  }

  SamCloseHandle(handle:handle);
 }

 return ret;
}


#---------------------------------------------------------#
# Function    : NetUserGetLocalGroups                     #
# Description : Return user's local group                 #
#---------------------------------------------------------#

function direct_NetUserGetLocalGroups (user, resolv)
{
 local_var ret, handle, domains, sid, handle2, rid, uhandle, rids, builtsid, handle3, aliases, aliases2;

 builtsid = raw_string (0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00);
 ret = NULL;

 handle = SamConnect2 ();
 if (!isnull(handle))
 {
  domains = SamEnumerateDomainsInSamServer (handle:handle);
  if (!isnull(domains))
  {
   sid = SamLookupDomainInSamServer (handle:handle, domain:domains[0]);
   if (!isnull(sid))
   {
    handle2 = SamOpenDomain (handle:handle, sid:sid, access:0x280);
    if (!isnull (handle2))
    {
     handle3 = SamOpenDomain (handle:handle, sid:builtsid, access:0x280);
     if (!isnull (handle3))
     {
      rid = SamLookupNamesInDomain (handle:handle2, user:user);
      if (!isnull(rid))
      {
       uhandle = SamOpenUser (handle:handle2, rid:rid, access:0x100);
       if (!isnull(uhandle))
       {
        rids = SamGetGroupsForUser (handle:uhandle);
        if (!isnull (rids))
        {
          aliases = SamGetAliasMemberShip (handle:handle2, sid:sid, rids:rids, urid:rid);
          aliases2 = SamGetAliasMemberShip (handle:handle3, sid:sid, rids:rids, urid:rid);

          if (resolv && !isnull(aliases))
            aliases = SamLookupIdsInDomain (handle:handle2, ids:aliases);

          if (resolv && !isnull(aliases2))
            aliases2 = SamLookupIdsInDomain (handle:handle3, ids:aliases2);

          if (isnull(aliases))
            aliases = aliases2;
          else if (!isnull(aliases2))
          {
            if (!isnull(aliases))
              aliases = make_list(aliases, aliases2);
            else
              aliases = aliases2;
          }

          ret = aliases;
        }

        SamCloseHandle(handle:uhandle);
       }
      }
     }
    }

    SamCloseHandle(handle:handle2);
   }
  }

  SamCloseHandle(handle:handle);
 }

 return ret;
}


#---------------------------------------------------------#
# Function    : NetLocalGroupGetMembers                   #
# Description : Return local group members                #
#---------------------------------------------------------#
function direct_NetLocalGroupGetMembers (group, domain)
{
 local_var ret, handle, domains, sid, handle2, rid, handle3, names, lsa, members, builtsid;

 builtsid = raw_string (0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00);
 ret = NULL;

 handle = SamConnect2 ();
 if (!isnull(handle))
 {
  handle2 = SamOpenDomain (handle:handle, sid:builtsid, access:0x200);
  if (!isnull (handle2))
  {
   rid = SamLookupNamesInDomain (handle:handle2, user:group);
   if (isnull(rid))
   {
    SamCloseHandle(handle:handle2); 
 
    domains = SamEnumerateDomainsInSamServer (handle:handle);
    if (!isnull(domains))
    {
      if ((!empty_or_null(domain) && domains[0] == domain) ||
          empty_or_null(domain))
      {
        sid = SamLookupDomainInSamServer (handle:handle, domain:domains[0]);
        if (!isnull(sid))
        {
          handle2 = SamOpenDomain (handle:handle, sid:sid, access:0x200);
          if (!isnull (handle2))
          {
            rid = SamLookupNamesInDomain (handle:handle2, user:group);
          }
        }
      }
    }
   }

   if (!isnull(rid))
   {
    handle3 = SamOpenAlias (handle:handle2, rid:rid, access:0x2000C);
    if (!isnull(handle3))
    {
     members = SamGetMembersInAlias (handle:handle3);
     if (!isnull(members))
     {
      lsa = LsaOpenPolicy (desired_access:0x20801);
      if (!isnull(lsa))
      {
       names = LsaLookupSid (handle:lsa, sid_array:members);
       if (!isnull(names))
       {
        ret = names;
       }

       LsaClose (handle:lsa);
      }
     }

     SamCloseHandle(handle:handle3);
    }
   }

   SamCloseHandle(handle:handle2);
  }

  SamCloseHandle(handle:handle);
 }

 return ret;
}



#---------------------------------------------------------#
# Function    : NetGroupGetUsers                          #
# Description : Return group members                      #
#---------------------------------------------------------#

function direct_NetGroupGetUsers (group)
{
 local_var ret, handle, domains, sid, handle2, rid, ghandle, members;

 ret = NULL;

 handle = SamConnect2 ();
 if (!isnull(handle))
 {
  domains = SamEnumerateDomainsInSamServer (handle:handle);
  if (!isnull(domains))
  {
   sid = SamLookupDomainInSamServer (handle:handle, domain:domains[0]);
   if (!isnull(sid))
   {
    handle2 = SamOpenDomain (handle:handle, sid:sid, access:0x200);
    if (!isnull (handle2))
    {
     rid = SamLookupNamesInDomain (handle:handle2, user:group);
     if (!isnull(rid))
     {
      ghandle = SamOpenGroup (handle:handle2, rid:rid, access:0x10);
      if (!isnull(ghandle))
      {
       members = SamGetMembersInGroup (handle:ghandle);
       if (!isnull(members))
       {
         ret = SamLookupIdsInDomain (handle:handle2, ids:members);
       }
       
       SamCloseHandle(handle:ghandle);
      }
     }
    }

    SamCloseHandle(handle:handle2);
   }
  }
  
  SamCloseHandle(handle:handle);
 }

 return ret;
}


#---------------------------------------------------------#
# Function    : NetUserGetInfo                            #
# Description : Return user's info                        #
#---------------------------------------------------------#

function direct_NetUserGetInfo (user)
{
 local_var ret, handle, domains, sid, handle2, rid, uhandle;

 ret = NULL;

 handle = SamConnect2 ();
 if (!isnull(handle))
 {
  domains = SamEnumerateDomainsInSamServer (handle:handle);
  if (!isnull(domains))
  {
   sid = SamLookupDomainInSamServer (handle:handle, domain:domains[0]);
   if (!isnull(sid))
   {
    handle2 = SamOpenDomain (handle:handle, sid:sid, access:0x200);
    if (!isnull (handle2))
    {
     rid = SamLookupNamesInDomain (handle:handle2, user:user);
     if (!isnull(rid))
     {
      uhandle = SamOpenUser (handle:handle2, rid:rid, access:0x11b);
      if (!isnull(uhandle))
      {
       ret = SamQueryInformationUser (handle:uhandle);
       SamCloseHandle(handle:uhandle);
      }
     }
    }

    SamCloseHandle(handle:handle2);
   }
  }
  
  SamCloseHandle(handle:handle);
 }

 return ret;
}


#---------------------------------------------------------#
# Function    : NetUserGetModals                          #
# Description : Return password policy                    #
# Return      : if level == 1                             #
#                 ret[0] = min pass len                   #
#                 ret[1] = pass history len               #
#                 ret[2] = max pass age                   #
#                 ret[3] = min pass age                   #
#                 ret[4] = force logoff                   #
#                 ret[5] = must meet complexity           #
#               if level == 3                             #
#                 ret[0] = lockout duration               #
#                 ret[1] = lockout observation window     #
#                 ret[2] = lockout threshold              #
# Note        : time in seconds (-1 if infinite)          #
#---------------------------------------------------------#

function direct_NetUserGetModals (level)
{
 local_var ret, handle, domains, sid, handle2, rid, uhandle, tmp;

 ret = NULL;

 handle = SamConnect2 ();
 if (!isnull(handle))
 {
  domains = SamEnumerateDomainsInSamServer (handle:handle);
  if (!isnull(domains))
  {
   sid = SamLookupDomainInSamServer (handle:handle, domain:domains[0]);
   if (!isnull(sid))
   {
    handle2 = SamOpenDomain (handle:handle, sid:sid, access:0x205);
    if (!isnull (handle2))
    {
     if (level == 1)
     {
      ret = SamQueryInformationDomain (handle:handle2, level:1);
      if (!isnull (ret))
      {
       tmp = SamQueryInformationDomain (handle:handle2, level:3);
       if (!isnull(tmp))
         ret[max_index(ret)] = tmp[0];
      }
     }
     else if (level == 3)
     {
      ret = SamQueryInformationDomain (handle:handle2, level:12);
     }
    }

    SamCloseHandle(handle:handle2);
   }
  }
  
  SamCloseHandle(handle:handle);
 }

 return ret;
}


