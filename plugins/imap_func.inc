#TRUSTED 531234be0826374625ff07dcf233a5fb2dc7034f72e3950a15bfe3cae3d23205393477c372abfa0a3aa33c8f09d02ce3ea0cfe1e227eb35cf32e55d8e777f518f0d54af340f6be3766608266069d2d04fabec80f356c8a9da15d323337248a8151227cafc09c76b33db10702db1c84cb02bb6465cffba165aad643a68710bb1a5dd8e804b2b13ca9b0e307865a475b8277ad6d47d61cd881ea82f5f6193643fea2ba741be00d57d66bfcdf4ab496c10d67b490be77b9f944b06e025428820d96bb119981c83a56e3d0f54ec7d0399af29730620ccea6ce0d4d61e5be6e16c7722ca05cbceb90ece55775010d03059d20c85c9bf3206a0693abcd02f0a29fbe6f55a526d15c82c90e27bc6fd8bbc9b19e1420ef043687bc28841d717d603a3fbd5d4a5f0482572691f4388366861d8f70ac18bcf5cfe807484f5ab4949603cc0bdcdb2d46769a6ba1bf4ddec68300c11931bad8635836068a99e9b75284478feec201f759f67b14632d28f8a41614d8a125cc0f9b8e924be2196317bc6ca2093083ab0cc26563bdeef451a9c7455e5e6d6c8897ccacc09ec4b4d0922f961f9b756e00f13b8fb72a2c57a7e248ead6e24c3fa79dd002f5143cc0d5a255de6ecff70dc4496a06c9d845ef15bdd254e1b990d84634a98b5e0b298b52f1232baa7aae87080f68938ab220d992d8b9c60f7f9a739e8f6f30261b58852dcf751051c96d
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# imap_func.inc
# Revision: 1.5


global_var _imap_tag;


function get_imap_banner (port)
{
  local_var sb, banner, soc;
  
  sb = string("imap/banner/", port);
  banner = get_kb_item(sb);
  if(banner) return (banner);
  if ( get_kb_item("imap/" + port + "/broken") ) 
	return NULL;

  if(! get_port_state(port)) return (0);
  soc = open_sock_tcp(port);
  if (! soc) {
	set_kb_item(name:"imap/" + port + "/broken", value:TRUE);
	return NULL;
	}
  banner =  recv_line(socket: soc, length:4096);
  close(soc);
  if(! banner ) {
	set_kb_item(name:"imap/" + port + "/broken", value:TRUE);
	return NULL;
	}
	
  
  	replace_kb_item(name: sb, value: banner);
  return(banner);
}


#----------------------------------------------------------------#
# Function    : imap_init_tag                                    #
# Description : Initializes the identifier sent with each        #
#               subsequent IMAP command.                         #
# Inputs      : 'val' => value to use as the identifier.         #
#               (optional)                                       #
# Return      : the new value of the identifier.                 #
# Notes       : If 'val' is not specified, a value based on the  #
#               basename of the plugin's filename is used.       #
# Usage       : imap_set_tag("a1");                              #
#----------------------------------------------------------------#
function imap_set_tag(val)
{
  if (isnull(val))
    _imap_tag = ereg_replace(pattern:"\.[^.]+$", replace:"", string:SCRIPT_NAME) + '1';
  else 
    _imap_tag = val;
  return _imap_tag;
}


#----------------------------------------------------------------#
# Function    : imap_get_tag                                     #
# Description : Returns the current value of the identifier      #
#               sent with each subsequent IMAP command.          #
# Inputs      : n/a                                              #
# Return      : the current value of the identifier.             #
# Notes       : none.                                            #
# Usage       : tag = imap_get_tag();                            #
#----------------------------------------------------------------#
function imap_get_tag()
{
  return _imap_tag;
}


#----------------------------------------------------------------#
# Function    : imap_increment_tag                               #
# Description : Increments the value of the identifier sent      #
#               with each subsequent IMAP command.               #
# Inputs      : n/a                                              #
# Return      : the new value of the identifier.                 #
# Notes       : If the identifier has not yet been initialized,  #
#               it will be and the new value will be returned.   #
# Usage       : tag = imap_increment_tag();                      #
#----------------------------------------------------------------#
function imap_increment_tag()
{
  if (isnull(_imap_tag)) return imap_set_tag();
  else return _imap_tag + 1;
}


#----------------------------------------------------------------#
# Function    : imap_is_response_ok                              #
# Description : Determines if the response was successful based  #
#                 on its response condition.                     #
# Inputs      : 'res' => a response structure. (optional)        #
# Return      : TRUE if successful (ie, 'OK'); FALSE otherwise.  #
# Notes       : none.                                            #
# Usage       : if (imap_is_response_ok(res)) ...                #
#----------------------------------------------------------------#
function imap_is_response_ok(res)
{
  if (
    !isnull(res) && 
    res['cond'] && 
    toupper(res['cond']) == 'OK'
  ) return TRUE;
  else return FALSE;
}


#----------------------------------------------------------------#
# Function    : imap_read_tagged_response                        #
# Description : Reads a tagged response from an IMAP server.     #
# Inputs      : 'socket' => an open socket. (required)           #
#               'retry' => number of times to retry reading a    #
#                 line in the event of a failure. (optional)     #
#               'last' => if set, return only the final line of  #
#                 response; otherwise, return everything.        #
#                 (optional)                                     #
# Return      : NULL if a match isn't found after 512 lines;     #
#                 otherwise, an array with the response          #
#                 condition and either the last line if 'last'   #
#                 is set or the concatenation of all lines       #
#                 read.                                          #
# Notes       : none                                             #
# Usage       : res = imap_read_tagged_response(socket:soc);     #
#----------------------------------------------------------------#
function imap_read_tagged_response(socket, retry, last)
{
  local_var m, n, r, ret, tag;

  if (isnull(socket)) return NULL;

  ret = make_array();
  r = recv_line(socket:socket, length:4096);

  n = 0;
  while (!r && n++ < retry)
    r = recv_line(socket:socket, length:4096);

  n = 0;
  ret['text'] = r;
  tag = '^'+imap_get_tag()+' (OK|BAD|NO)';

  while (r && !ereg(pattern:tag, string:r, icase:TRUE))
  {
    n++;
    r = recv_line(socket:socket, length:4096);
    if (strlen(r) == 0) break;
    if (n > 512)
      return NULL;
    if (last) ret['text'] = r;
    else ret['text'] = strcat(ret['text'], r);
  }
  if (m = eregmatch(pattern:tag, string:r, icase:TRUE))
    ret['cond'] = m[1];
  return ret;
}


#----------------------------------------------------------------#
# Function    : imap_send_cmd                                    #
# Description : Sends an IMAP command to a server and reads a    #
#               response.                                        #
# Inputs      : 'socket' => an open socket. (required)           #
#               'cmd' => a string to send. (required)            #
# Return      : the response received.                           #
# Notes       : Calling this command causes the identifier to    #
#               be incremented.                                  #
# Usage       : res = imap_send_cmd(                             #
#                 socket : soc,                                  #
#                 cmd    : 'CAPABILITY'                          #
#               );                                               #
#----------------------------------------------------------------#
function imap_send_cmd(socket, cmd)
{
  local_var r;

  if (isnull(socket) || isnull(cmd)) return NULL;

  send(socket:socket, data:imap_get_tag()+' '+cmd+'\r\n');
  r = imap_read_tagged_response(socket:socket);
  imap_increment_tag();
  return r;
}


#----------------------------------------------------------------#
# Function    : imap_close                                       #
# Description : Sends a LOGOUT command to an open socket and     #
#                 then closes it.                                #
# Inputs      : 'socket' => an open socket. (required)           #
# Return      : n/a                                              #
# Notes       : none                                             #
# Usage       : imap_close(socket:soc);                          #
#----------------------------------------------------------------#
function imap_close(socket)
{
  imap_send_cmd(socket:socket, cmd:'LOGOUT');
  close(socket);
}


#----------------------------------------------------------------#
# Function    : imap_starttls                                    #
# Description : Sends a STARTTLS command to an open socket.      #
# Inputs      : 'socket' => an open socket. (required)           #
#               'dont_read_banner' => read the initial service   #
#                 banner unless set to TRUE. (optional)          #
#               'encaps' => if specified, complete the SSL       #
#                 handshake using the type of encapsulation      #
#                 specified by 'encaps'. (optional)              #
# Return      : The socket if the connection could be upgraded   #
#               or NULL otherwise.                               #
# Notes       : Attempting to complete the SSL handshake will    #
#               always result in a failure if the function       #
#               'socket_negotiate_ssl()' is not defined.         #
# Usage       : if (imap_starttls(socket:soc, encaps:encaps))    #
#               {                                                #
#                 send(socket:soc, data:...                      #
#----------------------------------------------------------------#
function imap_starttls(socket, dont_read_banner, encaps)
{
  local_var r;

  if (!dont_read_banner)
  {
    r = recv_line(socket:socket, length:4096);
    if (!r) return NULL;
    imap_set_tag();
  }

  r = imap_send_cmd(socket:socket, cmd:'STARTTLS');
  if (!imap_is_response_ok(res:r)) return FALSE;

  if (encaps)
  {
    if (!defined_func("socket_negotiate_ssl")) return NULL;
    return socket_negotiate_ssl(socket:socket, transport:encaps);
  }
  return socket;
}
