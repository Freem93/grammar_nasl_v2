#TRUSTED 3717c59bf9709f03997555861456ab28fb689c88201841b3d56e9359f49304f2ea961ea2c08244834383d16d9d4f2935bad9689ced1479a3b82a3c19404749d4cd4ac2d7cb5790085a40afba033c9130212564199a53ec88d134792004dee0b921263fe20fbd52817a08d1d043cd7731c32ce9be19c9a9bace2150fcfb87b1b9bd677ed13758d027f51c3a98355f2579c1288c65255ece6cb86179295ebe33f52d264d896709ee027546ade87fc8ff6ca8db2b9ad71cdb10bf6584b2b569380cfde1a60e050519d7e34f36dcc6b637ebf689ec6a916dd4f5809eee2ce7f8066f3558bc690b9f7417dbec278ac68c74ed8cbd7c331415a02f83dfcdc983bc72c244c05a240342668db75cbab857fb19ab26c943c5b02eb85b4ef2c9b6f27fda7ab0b8f6565f0683c03243b4f4ab02de0b8c4bcc51c72ecbada7fde4445b5833a763f7f3b7b7f7c4fbfc1ca354a97d8381597a7dabfccf6ebfefb540c37836519aa39a96e5604225b9e6ae04f0d2c3d512ddfe661769ebeb77d83ce1faff5e07a2af9589d41d4cfa5ea5cfdb5ba7aba8efd4c18d6409e819496cd4a4b62094fbaf381237199c7ce32d2bb36843aadf9e35f5eba24259432dc8b51129b5ebaf3bacd51e2e276855bee8e603ce9e97c231fd96e3dc2f81ca80800eb98443f869cf5b93000e3e873fc8afc2ccda70e12866b362a17ccb5db2a9e6f1c0f73b02b20699
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
# smb_lsa.inc 
# Revision: 1.9
#

#==================================================================#
# Section 9. LSA API                                               #
#==================================================================#

#---------------------------------------------------------#
# Function    : LsaOpenPolicy                             #
# Description : Open LSA Policy                           #
# Note        : access mode is optional                   #
#---------------------------------------------------------#

function direct_LsaOpenPolicy (desired_access)
{
 local_var fid, ret, data, type, resp, rep, daccess;

 if (!isnull (desired_access))
   daccess = desired_access;
 else
   daccess = 0x000f0fff; 

 fid = bind_pipe (pipe:"lsarpc", uuid:"12345778-1234-abcd-ef00-0123456789ab", vers:0);
 if (isnull (fid))
   return NULL;

 data = class_parameter (ref_id:0x00020000, name:"\\" + session_get_hostname ()) +

        # LSA_OBJECT_ATTRIBUTES (NULL)
        raw_dword (d:0)          + # length
        raw_dword (d:0)          + # RootDirectory (HANDLE)
        raw_dword (d:0)          + # ObjectName (NULL)
        raw_dword (d:0)          + # Attributes
        raw_dword (d:0)          + # SecurityDescriptor (NULL Pointer)
        raw_dword (d:0)          + # SecurityQualityOfService (NULL Pointer)       

        # Desired Access
        raw_dword (d:daccess) ;
 data = dce_rpc_pipe_request (fid:fid, code:OPNUM_LSAOPENPOLICY, data:data);
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
# Function    : LsaQueryInformationPolicy                 #
# Description : Query Policy Information                  #
#                                                         #
# Supports    : PolicyAccountDomainInformation            #
#               PolicyPrimaryDomainInformation            #
#                                                         #
# return      : ret[0] hostname/domain                    #
#               ret[1] raw sid                            #          
#---------------------------------------------------------#

function direct_LsaQueryInformationPolicy (handle, level)
{
 local_var data, resp, rep, name, ret, len, ref_id, pad, length, size, i;
 local_var max_count, offset, actual_count, hostname, pos, count, sid, sid_ref_id, auditing;

 data = handle[0]                     +  # Handle
        raw_word (w:level) ;             # Info level
        
 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_LSAQUERYINFO, data:data);
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 10))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;


 ref_id = get_dword (blob:rep, pos:0);
 level = get_word (blob:rep, pos:4);


 if ((level == PolicyAccountDomainInformation) || (level == PolicyPrimaryDomainInformation))
 {

  if (strlen(rep) < 36)
    return NULL;

  # POLICY_ACCOUNT_DOMAIN_INFO
  pad = get_word (blob:rep, pos:6);

  # size is the total size of the remote buffer, length is data length in the buffer
  length = get_word (blob:rep, pos:8);
  size = get_word (blob:rep, pos:10);

  # ref_id = get_dword (blob:rep, pos:12); # string refid
  sid_ref_id = get_dword (blob:rep, pos:16); # sid refid

  # LSA_UNICODE_STRING
  max_count = get_dword (blob:rep, pos:20);
  offset = get_dword (blob:rep, pos:24);
  actual_count = get_dword (blob:rep, pos:28);

  if (strlen(rep) < 36 + length)
    return NULL;

  hostname = get_string2 (blob:rep, pos:32, len:length, _type:UNICODE_STRING);
    
  while ((length % 4) != 0)
    length ++;

  pos = 32 + length;

  if (sid_ref_id != 0)
  {
   # Domain SID
   count = get_dword (blob:rep, pos:pos);
   sid = substr (rep, pos+4, strlen(rep) - 5);
  }
  else
    sid = NULL;

  ret = NULL;
  ret[0] = hostname;
  ret[1] = sid;

  return ret;
 }

 if (level == PolicyAuditEventsInformation)
 {
  if (strlen(rep) != 64)
    return NULL;

  # values are filled with 0 (no auditing) if auditing is set to 0
  auditing = get_dword (blob:rep, pos:8);
  #if (auditing == 0)
  #  return NULL;

  ref_id = get_dword (blob:rep, pos:12);
  actual_count = get_dword (blob:rep, pos:16);
  max_count = get_dword (blob:rep, pos:20);

  if (actual_count != 9)
    return NULL;

  ret = NULL;
  for (i=0; i<9; i++)
     ret[i] = get_dword (blob:rep, pos:24+i*4);  

  return ret;
 } 
}


#---------------------------------------------------------#
# Function    : LsaQueryDomainInformationPolicy           #
# Description : Query Domain Policy Information           #
#                                                         #
# Supports    : PolicyDomainKerberosTicketInformation     #
#                                                         #
# return      : ret[0] - user logon restrictions          #
#               ret[1] - unknown                          #
#               ret[2] - service ticket lifetime (sec)    #
#               ret[3] - user ticket lifetime (sec)       #
#               ret[4] - user ticket renewal time (sec)   #
#               ret[5] - clock sync tolerance (sec)       #          
#---------------------------------------------------------#

function direct_LsaQueryDomainInformationPolicy (handle, level)
{
 local_var data, rep, resp, ref_id, ret;

 data = handle[0]                     +  # Handle
        raw_word (w:level) ;             # Info level
        
 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_LSAQUERYDOMAININFO, data:data);
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 10))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;


 ref_id = get_dword (blob:rep, pos:0);
 level = get_word (blob:rep, pos:4);


 if (level == PolicyDomainKerberosTicketInformation)
 {
  if (strlen(rep) != 60)
    return NULL;

  ret = NULL;
  ret[0] = get_dword (blob:rep, pos:8);
  ret[1] = get_dword (blob:rep, pos:12);
  ret[2] = convert_time_to_sec(time:substr(rep, 16, 23), no_zero:TRUE);
  ret[3] = convert_time_to_sec(time:substr(rep, 24, 31), no_zero:TRUE);
  ret[4] = convert_time_to_sec(time:substr(rep, 32, 39), no_zero:TRUE);
  ret[5] = convert_time_to_sec(time:substr(rep, 40, 47), no_zero:TRUE);

  return ret;
 }

 return NULL;
}


#---------------------------------------------------------#
# Function    : LsaLookupSid                              #
# Description : Translate PSID to UserNames               #
#               array of sid (InformationPolicy sid)      #
#                                                         #
# Return      : array of sid_type + domain + name         #
#               sid_type = raw_dword                      #
#---------------------------------------------------------#

function direct_LsaLookupSid (handle, sid_array)
{
 local_var data, resp, rep, name, ret, len, ref_id, level, pad, length, size;
 local_var max_count, offset, actual_count, hostname, pos, count, sid, sid_ref_id;
 local_var names, ref_idm, name_length, name_size, name_ref_id, sid_type, index, unknown;
 local_var sid_count, i;
 local_var domain_names, dompt, ref_list;

 domain_names = NULL;
 dompt = 0;

 ref_id = 0x00020000;
 if (isnull(sid_array) || !max_index(sid_array))
 {
   return NULL;
 }

 data = handle[0]                     +  # Handle

        # PSID Array
        raw_dword (d:max_index (sid_array))  + # number of sid in PSID Array
        raw_dword (d:ref_id)                 + # Referent ID
        raw_dword (d:max_index (sid_array)) ;  # max_count

 ref_id++;

 # ref_id
 foreach sid (sid_array)
 {
  data += raw_dword (d:ref_id);

  ref_id++;
 }

 foreach sid (sid_array)
 {
  count = ord(sid[1]);
  
  data += raw_dword (d:count)   +
          sid ;
 }

 data += raw_dword (d:0)        + # count = 0
         raw_dword (d:0)        + # NULL pointer (LSA_TRANSLATED_NAMES)

         raw_dword (d:1)        + # Level (nothing else seems to work)
         raw_dword (d:0)        ; # Num mapped ?
 #        raw_dword (d:0)        + # Unknown
 #        raw_dword (d:2) ;        # Unknown
        
 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_LSALOOKUPSID, data:data);
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 20))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if ((resp != STATUS_SUCCESS) && (resp != STATUS_SOME_NOT_MAPPED))
   return NULL;

 # LSA REF DOMAIN LIST Pointer
 ref_id = get_dword (blob:rep, pos:0);
 count = get_dword (blob:rep, pos:4);

 # Trust information array
 ref_id = get_dword (blob:rep, pos:8);
 max_count = get_dword (blob:rep, pos:12);
 count = get_dword (blob:rep, pos:16);

 pos = 20;

 # for each domain info
 pos = pos + count*12;

 for (i=0; i<count; i++)
 {
  if (strlen(rep) < pos + 12)
    return NULL;

  # name array
  max_count = get_dword (blob:rep, pos:pos+0);
  offset = get_dword (blob:rep, pos:pos+4);
  actual_count = get_dword (blob:rep, pos:pos+8);

  if (strlen(rep) < pos + 12 + actual_count*2)
    return NULL;

  domain_names[dompt++] = get_string2 (blob:rep, pos:pos+12, len:actual_count*2, _type:UNICODE_STRING);

  pos = pos+12+actual_count*2;

  if ((actual_count*2)%4)
    pos += 2;

  # SID
  sid_count = get_dword (blob:rep, pos:pos);
  if (strlen(rep) < pos + 4+8+sid_count*4)
   return NULL;

  sid = substr (rep, pos+4, pos+4+8+sid_count*4-1);
  pos = pos+4+8+sid_count*4;
 }

 # LSA_TRANSLATED_NAME_EX pointer
 count = get_dword (blob:rep, pos:pos);
 ref_id = get_dword (blob:rep, pos:pos+4);
 max_count = get_dword (blob:rep, pos:pos+8);

 pos = pos + 12;

 names = NULL;

 # for each names
 ref_list = NULL;
 for (i=0; i<count; i++)
 {
  if (strlen(rep) < pos + 20)
   return NULL;

  sid_type = get_word (blob:rep, pos:pos);
  names[i] = raw_dword (d:sid_type);
  length = get_word (blob:rep, pos:pos+4);
  size = get_word (blob:rep, pos:pos+6);
  ref_id = get_dword (blob:rep, pos:pos+8);
  index = get_dword (blob:rep, pos:pos+12);

  ref_list[i] = ref_id;

  if (index >= 0 && index < max_index(domain_names))
  {
    name = domain_names[index];
    names[i] += raw_dword (d:strlen(name)) + name;
  }

  pos = pos+16;
 }

 # we get names now
 for (i=0; i<count; i++)
 {
  if (ref_list[i] == 0)
  {
   name = sid2string(sid:sid_array[i]);
   names[i] += raw_dword(d:strlen(name)) + name;  
   continue;
  }

  if (strlen(rep) < pos + 12)
   return NULL;

  max_count = get_dword (blob:rep, pos:pos);
  offset = get_dword (blob:rep, pos:pos+4);
  actual_count = get_dword (blob:rep, pos:pos+8);

  if (strlen(rep) < pos + 12 + actual_count*2)
   return NULL;

  name = get_string2 (blob:rep, pos:pos+12, len:actual_count*2, _type:UNICODE_STRING);
  names[i] += raw_dword (d:strlen(name)) + name;
  if ((actual_count*2)%4)
    pos +=2;

  pos = pos+12+actual_count*2;
 }

 return names;
}



#---------------------------------------------------------#
# Function    : LsaLookupNames                            #
# Description : Translate UserNames to SID                #
#               array of usernames                        #
#                                                         #
# Return      : array of sid_type + rid                   #
#               sid_type = rid = raw_dword                #
#---------------------------------------------------------#

function direct_LsaLookupNames (handle, name_array)
{
 local_var data, resp, rep, name, ret, len, ref_id, level, pad, length, size;
 local_var max_count, offset, actual_count, hostname, pos, count, sid, sid_ref_id;
 local_var names, ref_idm, name_length, name_size, name_ref_id, sid_type, index, unknown;
 local_var sid_count, uname, i, rid, sid_tab, tmp_sid;

 ref_id = 0x00020000;

 data = handle[0]                     +  # Handle

        # Account array
        raw_dword (d:max_index (name_array))  + # number of sid in PSID Array
        raw_dword (d:max_index (name_array)) ;  # max_count

 ref_id++;

 # ref_id
 foreach name (name_array)
 {
  if (session_is_unicode() == 0)
  {
   session_set_unicode (unicode:1);
   uname = cstring (string:name,_null:1);
   session_set_unicode (unicode:0);
  }
  else
  {
   uname = cstring (string:name, _null:1);
  } 

  data += raw_word (w:strlen(uname)) +
          raw_word (w:strlen(uname)) +
          raw_dword (d:ref_id);

  ref_id++;
 }

 foreach name (name_array)
 {
  if (session_is_unicode() == 0)
  {
   session_set_unicode (unicode:1);
   uname = cstring (string:name,_null:1);
   session_set_unicode (unicode:0);
  }
  else
  {
   uname = cstring (string:name,_null:1);
  } 
  
  data += raw_dword (d:strlen(uname)/2)   +
          raw_dword (d:0)                 + # offset
          raw_dword (d:strlen(uname)/2);

  while ((strlen(uname)%4) != 0)
    uname += raw_byte (b:0);

  data += uname;
 }

 data += raw_dword (d:0)        + # count = 0
         raw_dword (d:0)        + # NULL pointer (LSA_TRANSLATED_NAMES)

         raw_dword (d:1)        + # Level (nothing else seems to work)
         raw_dword (d:0)        ; # Num mapped ?
        
 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_LSALOOKUPNAMES, data:data);
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 20))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if ((resp != STATUS_SUCCESS) && (resp != STATUS_NONE_MAPPED))
   return NULL;

 # LSA REF DOMAIN LIST Pointer
 ref_id = get_dword (blob:rep, pos:0);
 count = get_dword (blob:rep, pos:4);

 # Trust information array
 ref_id = get_dword (blob:rep, pos:8);
 max_count = get_dword (blob:rep, pos:12);
 count = get_dword (blob:rep, pos:16);

 pos = 20;

 sid_tab = NULL;

 # for each domain info
 
 for (i=0; i < count; i++)
 {
  if (strlen(rep) < pos + 24)
    return NULL;

  name_length = get_word (blob:rep, pos:pos);
  name_size = get_word (blob:rep, pos:pos+2);  # max size of name buffer (we are happy to know that)
  name_ref_id = get_dword (blob:rep, pos:pos+4);
  sid_ref_id = get_dword (blob:rep, pos:pos+8);

  # name array
  max_count = get_dword (blob:rep, pos:pos+12);
  offset = get_dword (blob:rep, pos:pos+16);
  actual_count = get_dword (blob:rep, pos:pos+20);

  if (strlen(rep) < pos + 28 + name_length)
    return NULL;

  name = substr (rep, pos+24, pos+24+name_length-1);
  pos = pos+24+name_length;

  while (name_length%4)
  {
   pos++;
   name_length++;
  }

  # SID
  sid_count = get_dword (blob:rep, pos:pos);

  if (strlen(rep) < pos + 4+8+sid_count*4)
   return NULL;

  sid_tab[i] = substr (rep, pos+4, pos+4+8+sid_count*4-1);

  pos = pos+4+8+sid_count*4;
 }

 # LSA_TRANSLATED_SID
 count = get_dword (blob:rep, pos:pos);
 ref_id = get_dword (blob:rep, pos:pos+4);
 max_count = get_dword (blob:rep, pos:pos+8);

 pos = pos + 12;
 sid = NULL;

 # for each names
 for (i=0; i<count; i++)
 {
  if (strlen(rep) < pos + 12)
   return NULL;

  sid_type = get_dword (blob:rep, pos:pos);
  rid = get_dword (blob:rep, pos:pos+4);
  index = get_dword (blob:rep, pos:pos+8);

  tmp_sid = sid_tab[i];
  sid[i] = tmp_sid[0] + raw_byte (b: ord(tmp_sid[1])+1) + substr(tmp_sid,2,strlen(tmp_sid)-1) + raw_dword (d:rid);

  pos = pos+12;
 }

 return sid;
}


#---------------------------------------------------------#
# Function    : LsaEnumerateAccountsWithUserRight         #
# Description : Get SID of User with Right 'right'        #
#               (string)                                  #
# Return      : array of sid                              #
#---------------------------------------------------------#

function direct_LsaEnumerateAccountsWithUserRight (handle, right)
{
 local_var data, rep, code, ret, resp, ref_id, size, pt, sid_count, count, max_count, sid_tab, i, total_len, pos;

 pt = raw_dword (d:0x20000) + # pointer ref id
      class_parameter (ref_id:0x00020000, name:right, size:TRUE, _null:FALSE);

 data = handle[0]                     +  # Handle
        pt ;                             # right pointer

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_LSAENUMERATEACCOUNTWITHUSERRIGHT, data:data);
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 16))
   return NULL;

 total_len = strlen(rep);
 
 resp = get_dword (blob:rep, pos:total_len);
 if (resp != STATUS_SUCCESS)
   return NULL;

 count = get_dword (blob:rep, pos:0);
 ref_id = get_dword (blob:rep, pos:4);
 max_count = get_dword (blob:rep, pos:8);

 pos= 12;
 for (i=0; i<count; i++)
 {
  if ((pos+4) > total_len)
    return NULL;

  ref_id = get_dword (blob:rep, pos:pos);
  pos += 4;
 }

 sid_tab = NULL;
 for (i=0; i<count; i++)
 {
  if ((pos+4) > total_len)
    return NULL;

  sid_count = get_dword (blob:rep, pos:pos);
  pos += 4;

  if ((pos+8+sid_count*4-1) > total_len)
    return NULL;

  sid_tab[i] = substr (rep, pos, pos+8+sid_count*4-1);

  pos = pos+8+sid_count*4;
 }

 return sid_tab;
}


#---------------------------------------------------------#
# Function    : LsaQuerySecurityObject                    #
# Description : Return security ACLs of the object        #
# Return      : security descriptor                       #
#---------------------------------------------------------#

function direct_LsaQuerySecurityObject (handle, type)
{
 local_var data, rep, code, ret, resp, ref_id, size;

 data = handle[0]                     +  # Handle
        raw_dword (d:type) ;             # Info level

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_LSASECURITYOBJECT, data:data);
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 16))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;


 ref_id = get_dword (blob:rep, pos:0);
 if (isnull(ref_id))
   return NULL;

 size = get_dword (blob:rep, pos:4); 
 ref_id = get_dword (blob:rep, pos:8);
 if (isnull(ref_id))
   return NULL;

 size = get_dword (blob:rep, pos:12);
 if (strlen(rep) < (size+16))
   return NULL;

 return parse_security_descriptor (blob:substr(rep, 16, strlen(rep)-5));
}


#---------------------------------------------------------#
# Function    : LsaClose                                  #
# Description : Close lsa handle                          #
# Return      : 1 on success                              #
#---------------------------------------------------------#

function direct_LsaClose (handle)
{
 local_var data, rep, code, ret;

 code = NULL;
 
 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_LSACLOSE, data:handle[0]);
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
