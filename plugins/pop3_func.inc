#TRUSTED 7d0b5ce877cf4573aed0ad3a20df8ec9344f8ab60c8a785e92a52b1d73c7182b20553d97f856905d597e462c02fd54a26f2f08652fc1d860ed0bcc00caa25de8854e5d3233fdfa85de8b1c4238a04e911c0d9e1d56258c04f2baa45ff32094356e20bd9eb24e4cbf3e3bc6c8566a1fc45345270379aac1ec29c5ad481ac3295f4b7fd0187e6c215690b956c396a1f3aa143cc3192e3b73b1b5326b9eec890969ebae33d1bff5603047877981ca52e7e4d1ac1c46f2f175a76509d6341e51512c8cff7f4de1fe5ed090a02381733561bc489bf247e3a6dea40cb252eab4c16872480eb46c635cac769111c6c105c605d8238a656578625a8d6c8737dcbe013b113845d5288e86b491a3a8abfc44d5aad3c3d8367b39996c11319830f98b4e902e7c8f32041ea86f5a6bec848b571c9e260c229e63e6a73b19db31540c5034edac5f6444d66f0be0f7e99f63c6021f28cd2b1e045d7473046ed01d41f78d95637de93d0561bec9dd1442019bc5337458edd68f14ba23d596b7c84304ceebecb0a68c634e6cdb109a96d58773c347175277d1fa71cf7e9653da0963885165b984a91756b7492a3c5580107cd8932a1a1ea6ec374cc166f1aa0ba34a88a2f1a65f87e0a6d7db24fe4b101de1b5d9996ce9c291d84bcc4131548b7154660b1b4aad16eab52b46b3035e92726f41f10534b31fdc20c2f5cca4e2ead1d09f5894c6b45d
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# pop3_func.inc
# Revision: 1.8


function get_pop3_banner (port)
{
  local_var sb, banner, soc;
  
  sb = string("pop3/banner/", port);
  banner = get_kb_item(sb);
  if(banner) return (banner);
  if ( get_kb_item("pop3/" + port + "/broken") ) 
	return NULL;

  if(! get_port_state(port)) return (0);
  soc = open_sock_tcp(port);
  if (! soc) {
	set_kb_item(name:"pop3/" + port + "/broken", value:TRUE);
	return NULL;
	}
  banner =  recv_line(socket: soc, length:4096);
  close(soc);
  if(! banner ) {
	set_kb_item(name:"pop3/" + port + "/broken", value:TRUE);
	return NULL;
	}
	
  
  	replace_kb_item(name: sb, value: banner);
  return(banner);
}


#----------------------------------------------------------------#
# Function    : pop3_is_response_ok                              #
# Description : Determines if the response was successful based  #
#                 on its response condition.                     #
# Inputs      : 'res' => a response structure. (optional)        #
# Return      : TRUE if successful (ie, 'OK'); FALSE otherwise.  #
# Notes       : none.                                            #
# Usage       : if (pop3_is_response_ok(res)) ...                #
#----------------------------------------------------------------#
function pop3_is_response_ok(res)
{
  if (
    !isnull(res) && 
    res['cond'] && 
    toupper(res['cond']) =~ "\+?OK"
  ) return TRUE;
  else return FALSE;
}


#----------------------------------------------------------------#
# Function    : pop3_read_response                               #
# Description : Reads a response from an pop3 server.            #
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
# Usage       : res = pop3_read_response(socket:soc);            #
#----------------------------------------------------------------#
function pop3_read_response(socket, retry, last)
{
  local_var m, n, r, pat, ret;

  if (isnull(socket)) return NULL;

  ret = make_array();
  r = recv_line(socket:socket, length:4096);

  n = 0;
  while (!r && n++ < retry)
    r = recv_line(socket:socket, length:4096);

  n = 0;
  ret['text'] = r;
  pat = "^(\+OK|-ERR) ";

  while (r && !ereg(pattern:pat, string:r, icase:TRUE))
  {
    n++;
    r = recv_line(socket:socket, length:4096);
    if (strlen(r) == 0) break;
    if (n > 512)
      return NULL;
    if (last) ret['text'] = r;
    else ret['text'] = strcat(ret['text'], r);
  }
  if (m = eregmatch(pattern:pat, string:r, icase:TRUE))
    ret['cond'] = m[1];
  return ret;
}


#----------------------------------------------------------------#
# Function    : pop3_send_cmd                                    #
# Description : Sends an pop3 command to a server and reads a    #
#               response.                                        #
# Inputs      : 'socket' => an open socket. (required)           #
#               'cmd' => a string to send. (required)            #
# Return      : the response received.                           #
# Notes       : Calling this command causes the identifier to    #
#               be incremented.                                  #
# Usage       : res = pop3_send_cmd(socket:soc, cmd:'CAPA');     #
#----------------------------------------------------------------#
function pop3_send_cmd(socket, cmd)
{
  if (isnull(socket) || isnull(cmd)) return NULL;

  send(socket:socket, data:cmd+'\r\n');
  return pop3_read_response(socket:socket);
}


#----------------------------------------------------------------#
# Function    : pop3_close                                       #
# Description : Sends a QUIT command to an open socket and then  #
#                 closes it.                                     #
# Inputs      : 'socket' => an open socket. (required)           #
# Return      : n/a                                              #
# Notes       : none                                             #
# Usage       : pop3_close(socket:soc);                          #
#----------------------------------------------------------------#
function pop3_close(socket)
{
  pop3_send_cmd(socket:socket, cmd:'QUIT');
  close(socket);
}


#----------------------------------------------------------------#
# Function    : pop3_starttls                                    #
# Description : Sends a STLS command to an open socket.          #
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
# Usage       : if (pop3_starttls(socket:soc, encaps:encaps))    #
#               {                                                #
#                 send(socket:soc, data:...                      #
#----------------------------------------------------------------#
function pop3_starttls(socket, dont_read_banner, encaps)
{
  local_var r;

  if (!dont_read_banner)
  {
    r = recv_line(socket:socket, length:4096);
    if (!r) return NULL;
  }

  r = pop3_send_cmd(socket:socket, cmd:'STLS');
  if (!pop3_is_response_ok(res:r)) return FALSE;

  if (encaps)
  {
    if (!defined_func("socket_negotiate_ssl")) return NULL;
    return socket_negotiate_ssl(socket:socket, transport:encaps);
  }
  return socket;
}
