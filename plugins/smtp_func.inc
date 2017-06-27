#TRUSTED 50c6447c88f9dd7c16d48a87d6bb5f15e2036c4c406677cd37134523bed7725ee6ea073f3187742fcd90392602e113beda6c0f4f65d4ae9eb06d23906554220748aa5718b62a959aa93f6f4b1ae776fc2aad21ef5987ee749b1d3475a886b058028c7467d7eb8d270ea3c49385f449cba35f7d5d2aefa1210449da6f3b39836dfe52a8d0db0747ec157bbd3e25008af2d469bfbddfad3ce9ec29d72b4c97b71f0d0823067a06be6fb6a966863b5249fc0fd6e9b0e4249f7107f5b6ea0f9feb8ee8055c87cf96a9e8758ee9202c4ed755468b7e25bdbe6bfd833f13798b76490073c22d622e3f00b5b4933cc0ad148cea0cd24ff183df732f5f55a0c014d4013fa607e2f38360b6a90f881bc4506e55d48ebdf2a594b25b680c6c8dfcbf90014a99c58dbed9bf675bf0710382bbe1b74a65d5c1da2996ea607a7f472dfcaf0496d4cc5afd5ef40bb9f05efc186a8ee00c84b18cdde4ce977c68e8c8b0dac4089096f0315fdbaf36b502b2a1e36710a83150afc0aa6e28792f139ca5b98001200a49089018e45d25d7b0be386ea1e0d3cc19f312ba23f810ccc4329d5412e40521ab05e9fdf75b9e5aab98e2843e954a4ede05bd0e818188043a6a3147b4cacfe532f953d4eec84a37cb15e880970c3a0a7e660efee6a06f1630a6407a0bdbe45682f95f94dd7b330d2c6859d3c029fd1abcbd405e2591441524545f7637f8f37e
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# smtp_func.inc
# Revision: 1.36

function smtp_close(socket)
{
  send(socket: socket, data: 'QUIT\r\n');
  smtp_recv_line(socket: socket);
  close(socket);
}

function smtp_open(port, helo, exit_on_fail)
{
  local_var	soc, data;

  if (isnull(exit_on_fail)) exit_on_fail = FALSE;

  soc = open_sock_tcp(port);
  if (! soc)
  {
    if (exit_on_fail) exit(0, "Can't open a socket on port "+port+".");
    else return NULL;
  }

  data = smtp_recv_banner(socket:soc);
  if (! data)
  {
    smtp_close(socket: soc);
    if (exit_on_fail) exit(1, "Failed to receive the SMTP banner from the service listening on port "+port+".");
    else return NULL;
  }
  
  if ( isnull(helo) ) return soc;

  send(socket:soc, data: strcat('HELO ', helo, '\r\n'));
  data = smtp_recv_line(socket: soc);
  if(! ereg(pattern:"^[2-3][0-9][0-9]", string:data))
  {
    smtp_close(socket: soc);
    if (exit_on_fail) exit(1, "The SMTP server listening on port "+port+" did not accept our HELO.");
    else return NULL;
  }

  return soc;  
}

function smtp_send_socket(socket, from, to, body)
{
  local_var buff;
  # display(string("smtp_send_socket from=", from, " to=", to, "\n"));
  # Just to be sure
  send(socket: socket, data: string("RSET\r\n"));
  buff = recv_line(socket: socket, length: 2048);
  # Here, we might test the return code
  if (from !~ ' *<.*> *') from = strcat('<', from, '>');
  send(socket: socket, data: string("MAIL FROM: ", from, "\r\n"));
  buff = recv_line(socket: socket, length: 2048);
  if (! ereg(pattern:"^2[0-9][0-9] ", string:buff)) { return (0); }
  
  if (to !~ ' *<.*> *') to = strcat('<', to, '>');
  send(socket: socket, data: string("RCPT TO: ", to, "\r\n"));
  buff = recv_line(socket: socket, length: 2048);
  if (! ereg(pattern:"^2[0-9][0-9] ", string:buff)) { return (0); }

  send(socket: socket, data: string("DATA\r\n"));
  buff = recv_line(socket: socket, length: 2048);
  if (! ereg(pattern:"^3[0-9][0-9] ", string:buff)) { return (0); }

  # Make sure that every line ends up with \r\n
  # This is not useful yet, as only two scripts send data to the SMTP server
  #body = ereg_replace(string: body, pattern: string("([^\r])\n"), replace: string("\\1\r\n"));
  send(socket: socket, data: body);
  send(socket: socket, data: string("\r\n.\r\n"));
  buff = recv_line(socket: socket, length: 2048);
  if (! ereg(pattern:"^2[0-9][0-9] ", string:buff)) { return (0); }
  return(1);
}

function smtp_send_port(port, from, to, body)
{
  local_var s, buff, ret, hostname;
  s = open_sock_tcp(port);
  if (! s) return (0);

  buff = recv_line(socket: s, length: 2048);
  if (strlen(buff) == 0 || buff !~ '^[1-5][0-9][0-9][ -]')
  {
    close(s);
    return 0;
  }
  hostname = get_kb_item('smtp/'+ port + '/helo');
  if (! hostname) hostname = 'nessus';
  send(socket: s, data: strcat('HELO ', hostname, '\r\n'));
  buff = recv_line(socket: s, length: 2048);
  if (strlen(buff) == 0 || buff !~ '^[1-5][0-9][0-9][ -]')
  {
    close(s);
    return 0;
  }
  # We should test the code
  ret = smtp_send_socket(socket: s, from: from, to: to, body: body);
  send(socket: s, data: string("QUIT\r\n"));
  close(s);
  return (ret);
}

function smtp_from_header()
{
 local_var fromaddr;
 fromaddr = get_kb_item("SMTP/headers/From");
 if (!fromaddr) fromaddr = "nessus@example.com";
 return (fromaddr);
}

function smtp_to_header()
{
 local_var toaddr;
 toaddr = get_kb_item("SMTP/headers/To");
 if (!toaddr) toaddr = string("postmaster@[", get_host_ip(), "]");
 return (toaddr);
}

function get_smtp_banner(port, exit_on_fail)
{
  local_var sb, banner, to, soc;

  if (isnull(exit_on_fail)) exit_on_fail = FALSE;

  sb = string("smtp/banner/", port);
  banner = get_kb_item(sb);
  if (banner) return (banner);
  if ( get_kb_item("smtp/" + port + "/broken") ) 
  {
    if (exit_on_fail) exit(1, "The SMTP server listening on port "+port+" is broken.");
    else return NULL;
  }

  if (!get_port_state(port)) 
  {
    if (exit_on_fail) exit(0, "Port "+port+" is not open.");
    else return (0);
  }
  soc = open_sock_tcp(port);
  if (! soc)
  {
    set_kb_item(name:"smtp/" + port + "/broken", value:TRUE);
    if (exit_on_fail) exit(0, "Can't open a socket on port "+port+".");
    else return NULL;
  }

  # nb: we'll handle failures here.
  banner = smtp_recv_banner(socket:soc, exit_on_fail:FALSE);
  close(soc);
  if (!banner)
  {
    set_kb_item(name:"smtp/" + port + "/broken", value:TRUE);
    if (exit_on_fail) exit(1, "The SMTP server listening on port "+port+" did not return a banner.");
    else return NULL;
  }

  replace_kb_item(name: sb, value: banner);
  return(banner);
}


function smtp_recv_line(socket, code, retry, last)
{
 local_var ret, n, r, pat;
 
 if (isnull(code))
   pat = "^[0-9][0-9][0-9]-";
 else
   pat = strcat("^", code, "-");

 ret = "";
 r = recv_line(socket:socket, length:4096);
 #
 n = 0;
 while (! r && n ++ < retry)
   r = recv_line(socket:socket, length:4096);
 #
 n = 0;
 ret = r;
 if(strlen(r) < 4) 
  return r;
  
 while(ereg(pattern: pat, string:r))
 {
  n = n + 1;
  r = recv_line(socket:socket, length:4096);
  if (strlen(r) == 0) break;
  if (n > 512)
   return NULL;
  if (last) ret = r;
  else      ret = strcat(ret, r);
 }
 return ret;
}

function smtp_recv_banner(socket, exit_on_fail)
{
  local_var b, oto, port, to;

  oto = NULL;
  if (defined_func("get_peer_name") && socket)
  {
    port = get_peer_name(socket);
    if (port) 
    {
      # nb: greetpause can NULL (missing), 0, or > 0.
      to = get_kb_item("smtp/"+port[1]+"/greetpause");
      if (isnull(to)) to = 30;
      if (to) oto = socket_set_timeout(socket:socket, timeout:to);
    }
  }

  b = smtp_recv_line(socket:socket, code:"220");
  if (!isnull(oto)) socket_set_timeout(socket:socket, timeout:oto);

  if (strlen(b) == 0 && exit_on_fail)
  {
    if (port) exit(1, "Failed to retrieve the banner from the SMTP server listening on port "+ port[1] +".");
    else exit(1, "Failed to retrieve the SMTP server's banner.");
  }
  return b;
}


#----------------------------------------------------------------#
# Function    : smtp_starttls                                    #
# Description : Sends a STARTTLS command to an open socket.      #
# Inputs      : 'socket' => an open socket. (required)           #
#               'dont_read_banner' => read the initial service   #
#                 banner unless set to TRUE. (optional)          #
#               'encaps' => if specified, complete the SSL       #
#                 handshake using the type of encapsulation      #
#                 specified by 'encaps'. (optional)              #
#               'exit_on_fail' => if specified, exit on a        #
#                 failure rather than returning NULL.            #
# Return      : The socket if the connection could be upgraded   #
#               or NULL otherwise.                               #
# Notes       : Attempting to complete the SSL handshake will    #
#               always result in a failure if the function       #
#               'socket_negotiate_ssl()' is not defined.         #
# Usage       : if (smtp_starttls(socket:soc, encaps:encaps))    #
#               {                                                #
#                 send(socket:soc, data:...                      #
#----------------------------------------------------------------#
function smtp_starttls(socket, dont_read_banner, encaps, exit_on_fail)
{
  local_var data;

  if (isnull(exit_on_fail)) exit_on_fail = FALSE;

  if (!dont_read_banner)
  {
    data = smtp_recv_banner(socket:socket);
    if (!data)
    {
      if (exit_on_fail) exit(1, "Failed to get the banner from the SMTP server.");
      else return NULL;
    }

    send(socket:socket, data:'HELO '+this_host()+'\r\n');
    data = smtp_recv_line(socket:socket);
    if(!ereg(pattern:"^[2-3][0-9][0-9]", string:data))
    if (!data)
    {
      if (exit_on_fail) exit(1, "The SMTP server did not accept our HELO.");
      else return NULL;
    }
  }

  send(socket:socket, data:'STARTTLS\r\n');
  data = smtp_recv_line(socket:socket);
  if (strlen(data) < 4) 
  {
    if (exit_on_fail) exit(1, "The SMTP server did not send back a valid response to a STARTTLS command.");
    else return NULL;
  }

  if (substr(data, 0, 2) != "220") return FALSE;

  if (encaps)
  {
    if (!defined_func("socket_negotiate_ssl")) 
    {
      if (exit_on_fail) exit(1, "Failed to negotiate an SSL / TLS connection after sending a STARTTLS command.");
      else return NULL;
    }
    return socket_negotiate_ssl(socket:socket, transport:encaps);
  }
  return socket;
}
