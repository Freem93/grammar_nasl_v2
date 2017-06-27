#TRUSTED 01b5284b583b1b1b29d42f3cbe95eb73edb548137d57ed798ade19180b01eead9e1247f397a8ac0a783b8b636e88ec458216389ddff5fccd2b2e44cf9f49417b9d9af83956c09c259346805da0038e6f5530514738b2c6f817f573bba87e32f525f58ee55e58d2d090502134de457aa37a43f4c46255833c18b3170190c6d5b9890493e3453f653c522c927f591727d70e2848c080fac1cf39eb9231a954ea28e9b5ca4e05b9aaf9b18ec7c3cf5541354ef17c7243887656944569f4a1900f4ac28e0339f25142f582d3ab35799e1f3e142eced35afd7d52a0bb19ddeaaab8ff7dcb9e58c0ff55c4580dd14d896362dae94c5f59ce49bfb073426a1faed219b47c043ecff0177e5b4a9499537359eb0b0e9991b4d018f8190290ba5543e4742e8ba01308056e8fa295b4ff1034a8c2d9cc76067c10007acf3a4dfbd1ff38980eb742668129986fb38df5e3675074ab133c0c4980d571e65552647d3b1dcf7a98a5268e786cb968f0dbcc5e1988d4dea7e00e1747bc5dada0fd31ea7e444f486580be6be584326ef115d1c6d844bf4d0221d1487005aea507efff189c6db7aaf0e616c7f865f674d4f3b0c8261d241a8d315d551d9d35a5d752fa998cecb845d8043dbe0e3ced04ff66de70270112b0c9ff3a2a9f3ae4a269729243d1e0f392adf81cf9b8986d7d8785aaf419de61515810df8703dd185033601386de507b6e3c
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# acap_func.inc
# Revision: 1.3
#

global_var _acap_tag;

#----------------------------------------------------------------#
# Function    : acap_set_tag                                     #
# Description : Initializes the identifier sent with each        #
#               subsequent ACAP command.                         #
# Inputs      : 'val' => value to use as the identifier.         #
#               (optional)                                       #
# Return      : the new value of the identifier.                 #
# Notes       : If 'val' is not specified, a value based on the  #
#               basename of the plugin's filename is used.       #
# Usage       : acap_set_tag("a1");                              #
#----------------------------------------------------------------#
function acap_set_tag(val)
{
  if (isnull(val))
    _acap_tag = "nessus1";
  else
    _acap_tag = val;

  return _acap_tag;
}


#----------------------------------------------------------------#
# Function    : acap_get_tag                                     #
# Description : Returns the current value of the identifier      #
#               sent with each subsequent ACAP command.          #
# Inputs      : n/a                                              #
# Return      : the current value of the identifier.             #
# Notes       : none.                                            #
# Usage       : tag = acap_get_tag();                            #
#----------------------------------------------------------------#
function acap_get_tag()
{
  return _acap_tag;
}


#----------------------------------------------------------------#
# Function    : acap_increment_tag                               #
# Description : Increments the value of the identifier sent      #
#               with each subsequent ACAP command.               #
# Inputs      : n/a                                              #
# Return      : the new value of the identifier.                 #
# Notes       : If the identifier has not yet been initialized,  #
#               it will be and the new value will be returned.   #
# Usage       : tag = acap_increment_tag();                      #
#----------------------------------------------------------------#
function acap_increment_tag()
{
  local_var match;

  if (isnull(_acap_tag))
    return acap_set_tag();

  match = eregmatch(string:_acap_tag, pattern:"^([^0-9]+)([0-9]+)$");
  if (isnull(match))
    return NULL;

  _acap_tag = match[1] + (int(match[2]) + 1);

  return _acap_tag;
}

function acap_command(command, socket)
{
  local_var match, req, res, tag;

  # Send command to server.
  tag = acap_increment_tag();
  req = tag + ' ' + command + '\r\n';
  send(socket:socket, data:req);

  # Read response from server.
  while (res = recv_line(socket:socket, length:2048))
  {
    res = chomp(res);
    match = eregmatch(pattern:"^(\*|" + tag + ") (ALERT|BAD|BYE|NO|OK)", string:res, icase:TRUE);
    if (!isnull(match))
      return toupper(match[2]);
  }

  return NULL;
}


function acap_open(port, socket)
{
  local_var res;

  if (!socket)
  {
    if (isnull(port))
      return NULL;

    socket = open_sock_tcp(port);
    if (!socket)
      return NULL;
  }

  res = recv_line(socket:socket, length:1024);
  if (!strlen(res))
  {
    close(socket);
    return NULL;
  }

  if (!isnull(port))
    replace_kb_item(name:"acap/" + port + "/banner", value:res);

  acap_set_tag();

  return socket;
}


#----------------------------------------------------------------#
# Function    : acap_starttls                                    #
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
# Usage       : if (acap_starttls(socket:soc, encaps:encaps))    #
#               {                                                #
#                 send(socket:soc, data:...                      #
#----------------------------------------------------------------#
function acap_starttls(socket, dont_read_banner, encaps)
{
  local_var match, req, res, tag;

  if (!socket)
    return NULL;

  if (!dont_read_banner)
  {
    socket = acap_open(socket:socket);
    if (!socket)
      return NULL;
  }

  res = acap_command(socket:socket, command:"STARTTLS");

  # If the server says "BYE", just close the connection.
  if (isnull(res) || res == "BYE")
  {
    return NULL;
  }

  # If the server doesn't accept STARTTLS, shutdown properly.
  if (res != "OK")
  {
    acap_close(socket:socket);
    return NULL;
  }

  if (encaps)
  {
    if (!defined_func("socket_negotiate_ssl")) return NULL;
    return socket_negotiate_ssl(socket:socket, transport:encaps);
  }

  return socket;
}


function acap_close(socket)
{
  if (!socket)
    return NULL;

  return acap_command(socket:socket, command:"LOGOUT");
}
