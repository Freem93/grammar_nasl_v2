###
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
# afp_func.inc
# $Revision: 1.5 $
#
# @include byte_func.inc
###

global_var request_id, last_error, AFPSocket;

request_id = 0;

Request = 0x00;
Reply   = 0x01;


CloseSession = 1;
Command = 2;
GetStatus = 3;
OpenSession = 4;
FPGetSrvrParms = 16;
FPLogin = 18;
FPLogout = 20;
FPCloseVol = 2;
FPOpenVol = 24;
FPEnumerateExt2 = 68;

##
# Converts a string into a Pascal string (one byte length followed by string)
#
# @anonparam string string to convert
#
# @return pascal string representation of "string"
##
function pstring()
{
 return strcat(mkbyte(strlen(_FCT_ANON_ARGS[0])), _FCT_ANON_ARGS[0]);
}

##
# Generates Data Stream Interface (DSI) packet data
#
# @param flags indicates whether the packet is a request or reply
# @param command the DSI command code
# @param data_offset when using the DSIWrite command, the number of bytes in the packet representing
#                    AFP command information. For all other commands, this should be set to 0
# @param reserved reserved. should be set to 0.
# @param data payload (limited DSI data or AFP header)
#
# @return newly created DSI packet data
##
function DSI_Packet(flags, command, data_offset, reserved, data)
{
 local_var ret;

 request_id++;

 ret = mkbyte(flags) +
       mkbyte(command) +
       mkword(request_id) +
       mkdword(data_offset) +
       mkdword(strlen(data)) +
       mkdword(reserved) +
       data;

 return ret;
}

##
# Extracts the error code field from the given DSI packet data
#
#
# @return error code contained in 'dsi_data'
##
function DSI_GetErrorCode()
{
 return getdword(blob:_FCT_ANON_ARGS[0], pos:4);
}

##
# Extracts the data length field from the given DSI packet data
#
# @anonparam dsi_data DSI packet data to parse
#
# @return data length contained in 'dsi_data'
##
function DSI_GetDataLen()
{
 return getdword(blob:_FCT_ANON_ARGS[0], pos:8);
}


##
# Sends the given DSI packet data and receives the response
#
# @anonparam pkt DSI packet data to send
#
# @return server response to 'pkt'
##
function DSI_SendRecv()
{
 local_var pkt, buf, len;
 local_var buf2;

 pkt = _FCT_ANON_ARGS[0];

 if ( send(socket:AFPSocket, data:pkt) != strlen(pkt) )
 {
  last_error = -1;
  return NULL;
 }
 buf = recv(socket:AFPSocket, length:16);
 if ( strlen(buf) != 16 ) {
   last_error = -1;
   return NULL;
 }
 len = DSI_GetDataLen(buf);
 buf2 = recv(socket:AFPSocket, length:len, min:len);
 if ( strlen(buf2) != len ) {
      last_error = -1;
   return NULL;
 }
 last_error = DSI_GetErrorCode(buf);
 return buf + buf2;
}

##
# Gets the last error code seen in a DSI packet
#
# @return the last DSI error code received
##
function DSI_LastError()
{
 return last_error;
}


##
# Gets information about the server
#
# @return server response to DSIGetStatus command
##
function GetStatus()
{
 local_var pkt;

 pkt = DSI_Packet(flags:Request, command:GetStatus, data:'\x00\x0f');
 return DSI_SendRecv(pkt);
}

##
# Parses the status reply
#
# @return An array of the parsed Results
##
function GetStatusParseReply()
{
  local_var pkt, pos, ret, i, j, k;
  local_var len, value, type, address;

  ret = make_array();
  pos = 0;

  pkt = _FCT_ANON_ARGS[0];

  if (isnull(pkt))
    return NULL;

  ret["flags"] = getbyte(blob:pkt, pos:pos); pos++;
  ret["cmd"] = getbyte(blob:pkt, pos:pos); pos++;
  ret["r_id"] = getword(blob:pkt, pos:pos); pos += 2;
  ret["error_code"] = getdword(blob:pkt, pos:pos); pos += 4;
  ret["length"] = getdword(blob:pkt, pos:pos); pos += 4;
  ret["reserve"] = getdword(blob:pkt, pos:pos); pos += 4;

  ret["machine_offset"] = getword(blob:pkt, pos:pos); pos += 2;
  ret["version_offset"] = getword(blob:pkt, pos:pos); pos +=2;
  ret["uams_offset"] = getword(blob:pkt, pos:pos); pos += 2;
  ret["icon_offset"] = getword(blob:pkt, pos:pos); pos += 2;
  ret["flag"] = getword(blob:pkt, pos:pos); pos += 2;
  ret["server_name_length"] = getbyte(blob:pkt, pos:pos); pos++;
  ret["server_name"] = substr(pkt, pos, pos + ret["server_name_length"] - 1); pos += ret["server_name_length"];
  ret["signature_offset"] = getword(blob:pkt, pos:pos); pos += 2;
  ret["network_address_offset"] = getword(blob:pkt, pos:pos); pos += 2;
  ret["directory_services_offset"] = getword(blob:pkt, pos:pos); pos += 2;
  ret["utf8_server_name_offset"] = getword(blob:pkt, pos:pos); pos += 2;

  #unknown 2 bytes
  pos += 2;

  ret["server_type_length"] = getbyte(blob:pkt, pos:pos); pos++;
  ret["server_type"] = substr(pkt, pos, pos + ret["server_type_length"] - 1); pos += ret["server_type_length"];

  ret["version_list_count"] = getbyte(blob:pkt, pos:pos); pos++;
  ret["version_list"] = make_list();
  
  for (i = 0; i < ret["version_list_count"]; i++)
  {
    len = getbyte(blob:pkt, pos:pos); pos++;
    ret["version_list"][i] = substr(pkt, pos, pos + len - 1); pos += len;
  }

  ret["uams_list_count"] = getbyte(blob:pkt, pos:pos); pos++;
  ret["uams_list"] = make_list();
  
  for (i = 0; i < ret["uams_list_count"]; i++)
  {
    len = getbyte(blob:pkt, pos:pos); pos++;
    ret["uams_list"][i] = substr(pkt, pos, pos + len - 1); pos += len;
  }

  ret["server_signature"] = hexstr(substr(pkt, pos, pos + 16 - 1)); pos += 16;

  ret["address_list_count"] = getbyte(blob:pkt, pos:pos); pos++;
  ret["address_list"] = make_list();

  for (i = 0; i < ret["address_list_count"]; i++)
  {
    len = getbyte(blob:pkt, pos:pos); pos++;
    type = getbyte(blob:pkt, pos:pos); pos++;

    # IP + port address
    if (type == 2)
    {
      address = make_list();
      value = "";

      address[0] = getbyte(blob:pkt, pos:pos); pos++;
      address[1] = getbyte(blob:pkt, pos:pos); pos++;
      address[2] = getbyte(blob:pkt, pos:pos); pos++;
      address[3] = getbyte(blob:pkt, pos:pos); pos++;

      value = join(address, sep:'.');

      value += ":";
      value += getword(blob:pkt, pos:pos); pos += 2;
    }
    # IP6 + port address
    else if (type == 7)
    {
      value = "";
      j = 0;
      address = hexstr(substr(pkt, pos, pos + 16 - 1)); pos += 16;

      for (k = 0; k < strlen(address); k++)
      {
        value += address[k];
        j++;

        if (j == 4 && (k + 1) != strlen(address))
        {
          j = 0;
          value += ":";
        }
      }

      value += ":";
      value += getword(blob:pkt, pos:pos); pos += 2;
    }
    # DNS name
    else if (type == 4)
    {
      value = substr(pkt, pos, pos + (len - 3)); pos += len;
    }

    ret["address_list"][i] = value;
  }

  return ret;
}

##
# Establish a new DSI session
#
# @return server response to DSIOpenSession command
##
function OpenSession()
{
 local_var pkt;
 AFPSocket = _FCT_ANON_ARGS[0];
 if ( isnull(AFPSocket) ) return NULL;

 pkt = DSI_Packet(flags:Request, command:OpenSession, data:mkbyte(1) +
                 mkbyte(4) +
                 mkdword(1024));
 return DSI_SendRecv(pkt);
}

##
# Closes an established DSI session
#
# @return server response to DSICloseSession command
##
function CloseSession()
{
 local_var pkt;

 pkt = DSI_Packet(flags:Request, command:CloseSession);
 pkt = DSI_SendRecv(pkt);
 close(AFPSocket);
 return pkt;
}

##
# Generates FPLogin request data, used to establish an AFP session with the server
#
# @remark this function is not fully implemented, only the "No User Authent"
#         user authentication mechanism (UAM) is implemented
##
function AFPLogin(login, password)
{
 # TODO
 return mkbyte(FPLogin) +
  pstring("AFP3.1") +
  pstring("No User Authent");

}

##
# Establishes an AFP session with the server.
#
# @remark authentication has not been implemented in this include file. see [AFPLogin]
#
# @return server response to FPLogin request
##
function FPLogin()
{
 local_var pkt;

 pkt = DSI_Packet(flags:Request, command:Command, data:AFPLogin());
 return DSI_SendRecv(pkt);
}

##
# Terminates a session with the server
#
# @return server response to FPLogout request
##
function FPLogout()
{
 local_var pkt;

 pkt = DSI_Packet(flags:Request, command:Command, data:mkbyte(FPLogout));
 return DSI_SendRecv(pkt);
}

##
# Gets server parameters
#
# @return server response to FPGetSrvrParms request
##
function FPGetSrvrParms()
{
 local_var pkt;
 pkt = DSI_Packet(flags:Request, command:Command, data:mkbyte(FPGetSrvrParms) + mkbyte(0));
 return DSI_SendRecv(pkt);
}

##
# Extracts the list of volume names from a FPGetSrvrParms response
#
# @anonparam pkt FPGetSrvrParms response packet data to parse
#
# @return the list of volume names contained in 'pkt'
##
function FPGetSrvrParmsParseReply()
{
 local_var pkt;
 local_var ret;
 local_var data;
 local_var num_volumes;
 local_var i;
 local_var pos;
 local_var flags;
 local_var len;

 pkt = _FCT_ANON_ARGS[0];
 data = substr(pkt, 16 + 4, strlen(pkt) - 1);
 num_volumes = ord(substr(data, 0, 1));
 pos = 1;
 ret = make_list();
 for ( i = 0 ; i < num_volumes ; i ++ )
 {
  flags = getbyte(blob:data, pos:pos); pos++;
  len   = getbyte(blob:data, pos:pos); pos++;
  ret[i] = substr(data, pos, pos + len - 1);
  pos += len;
 }
 return ret;
}

##
# Opens a volume
#
# @anonparam volume_name name of the volume to open
#
# @return server response to FPOpenVol request
##
function FPOpenVol()
{
 local_var pkt;
 pkt = DSI_Packet(flags:Request, command:Command, data:mkbyte(FPOpenVol) + mkbyte(0) + mkword(0x0020) + pstring(_FCT_ANON_ARGS[0]) + mkbyte(0));
 return DSI_SendRecv(pkt);
}


##
# Extracts the volume ID from a FPOpenVol reply block
#
# @anonparam pkt FPOpenVol response packet data to parse
#
# @return volume ID contained in 'pkt'
##
function FPOpenVolParseReply()
{
 return getword(blob:_FCT_ANON_ARGS[0], pos:strlen(_FCT_ANON_ARGS[0]) - 2);
}

##
# Closes a volume
#
# @anonparam volume_id ID of the volume to close
#
# @return server response to FPCloseVol request
##
function FPCloseVol()
{
 local_var pkt;
 pkt = DSI_Packet(flags:Request, command:Command, data:mkbyte(FPCloseVol) + mkbyte(_FCT_ANON_ARGS[0]) );
 return DSI_SendRecv(pkt);
}

##
# Lists the contents of a directory
#
# @param volume_id ID of the volume the directory is located on
# @param DID identifier for the directory to list
# @param path pathname to the desired directory
#
# @return server response to FPEnumerateExt2 request
##
function FPEnumerateExt2(volume_id, DID, path)
{
 local_var pkt;
 pkt = DSI_Packet(flags:Request, command:Command, data:mkbyte(FPEnumerateExt2) + mkbyte(0) + mkword(volume_id) + mkdword(DID) + mkword(0x42) + mkword(0x42) + mkword(20) + mkdword(1) + mkdword(5280) + mkbyte(0x03) + mkdword(0x08000103) + mkword(strlen(path)) + path);
 return DSI_SendRecv(pkt);
}

##
# Gets the list of files contained in a FPEnumerateExt2 response block
#
# @anonparam pkt FPEnumerateExt2Parse response packet data to parse
#
# @return a list of files contained in 'pkt'
##
function FPEnumerateExt2Parse()
{
 local_var pkt, data;
 local_var cnt;
 local_var pos;
 local_var i;
 local_var j, n;
 local_var sz;
 local_var struct;
 local_var ret;

 pkt = _FCT_ANON_ARGS[0];
 data = substr(pkt, 16 + 2 + 2, strlen(pkt) - 1);
 pos = 0;
 cnt = getword(blob:data, pos:pos); pos += 2;
 ret = make_list();
 for ( i = 0 ; i < cnt ; i ++ )
 {
  sz = getword(blob:data, pos:pos);
  struct = substr(data, pos + 10, pos + sz - 1);
  n = strlen(struct);
  for ( j = 0 ; j < n ; j ++ )
   if ( ord(struct[j]) != 0 ) break;

  if ( j < n && ord(struct[j]) < strlen(struct))
  {
   ret[max_index(ret)] = substr(struct, j + 1, j + ord(struct[j]) );
  }

  pos += sz;
  struct = NULL;
 }
 return ret;
}
