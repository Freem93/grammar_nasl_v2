#TRUSTED 3528af3e6cf2ba99ecf38807a81aa6e64dc33a35fc890af6e1250c5073253db09467fe828adc396c5bb94b3e8fc0781b639ce1a331b08ab8db5e4c6d49da6cbad23c7a44f13853a6e3d96dc78795e56a11f55c5831e40d9621d73e19539524bda2754fbc98d27b82e0caed208d07fdcdb4bc54802fd2975ea6ec50083eec0cc7683c47ac38e793cc12c68476231f58b5e209ffd70010eec581ec47c737927b341eed385d0ce746b0745a4a2861a1617d48610002422d72a8981fd3082437a0eda81152f8c3760cf1110442402a5ed430211d17449c04dce01281e811d698abca95dd14d1211972e0683287c26f26947f82e3579e754f5af19834ea0f4a0afac2101a46e0a9f4a446d186c68e86b9b5b6dfa54a326208e3f17cdd74eac72de902268a57ef69a66c35d1f7ea533f6f6214c5dd84910f6f466bf4b14e3d78d81f400b3d9ac7e9279a053a1e3cf48597061fa5cdde0cde88d67d44ec5c2c6fb097444e26937927875ca067a23486845023d52e217b433e9b378a9af6a0aeafdbcb55b0cebc375d14570dc117b0b2d86d956f51f1866ba2571158657ce3c15dc9bd99763426c3ffd51ae305a2e3bb16dde9741da36239680e88031615cdd733eddf9a80f32f85da0795be4b8e74742e532e2bf4d5d89a542510372e0d5b4bde03b414f7326442fe8a0bbcbcc14f2c638eb1488b052c10f8bb1237c327a4398e4062fb
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# ftp_func.inc
# Revision: 1.52

function ftp_close(socket)
{
  send(socket:socket, data:'QUIT\r\n');
  close(socket);
}

function get_ftp_banner(port)
{
 local_var lines, sb, banner, soc, str;
 
 lines = 0;
  sb = string("ftp/banner/", port);
  banner = get_kb_item(sb);
  if (banner) return(banner);
  if ( get_kb_item("ftp/" + port + "/broken") ) return NULL;

  if (! get_port_state(port)) return (0);
  soc = open_sock_tcp(port);
  if(!soc) {
	set_kb_item(name:"ftp/" + port + "/broken", value:TRUE);
	return NULL;
	}
  banner = ftp_recv_line(socket:soc);
  ftp_close(socket: soc);
  if ( ! banner ) 
  {
	set_kb_item(name:"ftp/" + port + "/broken", value:TRUE);
	return NULL;
  }
	replace_kb_item(name: sb, value: banner);
  return(banner);
}

function ftp_send_cmd(socket, cmd)
{
 send(socket:socket, data:cmd + '\r\n');
 return ftp_recv_line(socket:socket);
}

function ftp_recv_line(socket, retry)
{
 local_var	n, r, res;

 r = recv_line(socket:socket, length:65535);
 n = 0;
 while (strlen(r) == 0 && n ++ < retry)
  r = recv_line(socket:socket, length:65535);
 if(strlen(r) < 4) 
  return(r);

 n = 0;
 res = r;
 # Some FTP servers have a broken banner on several lines with a leading space
 while ((strlen(r) > 3 && r[3] == "-") || (strlen(r) >= 3 && r[0] == ' '))
 {
  n ++;
  r = recv_line(socket:socket, length:65535);
  if(n > 255)
   return(NULL);
  res = res + r;
 }
 return(res);
}

function ftp_recv_listing(socket)
{
 local_var	n, r, buf;
 n = 0;
 r = recv_line(socket:socket, length:65535);
 buf = r;
 while(strlen(r))
 {
  n ++;
  if(n > 4096)
   return(NULL);
  r = recv_line(socket:socket, length:65535);
  buf += r; 
 }
 return buf;
}

function ftp_recv_data(socket, line)
{
 local_var bytes, min;
 
 if(line != NULL )
 {
  if (ereg(pattern:"^150.*\(([0-9]*) .*\)", string:line))
   bytes = ereg_replace(pattern:"^150.*\(([0-9]*) .*\)", string:line, replace:"\1");
 }
 
 if(!bytes){ bytes = 8192; min = 1; }
 else { min = int(bytes); bytes = int(bytes); }
 
 return recv(socket:socket, min:min, length:bytes);
}

#
# Logs into the remote FTP server
#
function ftp_authenticate(socket, user, pass)
{
 local_var r;
 r = ftp_recv_line(socket:socket); # Receive the banner
 send(socket:socket, data:'USER ' + user + '\r\n');
 r = ftp_recv_line(socket:socket);
 if ( 
  strlen(r) < 4 ||
  (r[0] != '3' && r[0] != '2')
 ) return 0;
 if (strlen(r) > 3 && substr(r, 0, 2) == '230') return 1;

 send(socket:socket, data:'PASS ' + pass + '\r\n');
 r = ftp_recv_line(socket:socket);
 if ( strlen(r) < 4 || r[0] != '2' ) return 0;
 else return 1;
}

#
# Returns the port opened on the remote side through a 'PASV' command
#
function ftp_pasv(socket)
{
 local_var r, port, array;

 if ( TARGET_IS_IPV6 )
 {
  send(socket:socket, data:'EPSV\r\n');
   r = ftp_recv_line(socket:socket);
   if ( r[0] != '2' ) return 0;
   port = egrep(pattern:"^2.9 .*\(\|\|\|[0-9]+\|\)", string:r);
   if ( ! port ) return 0;
   array = eregmatch(pattern:"^2.9 .*\(\|\|\|([0-9]+)\|\)", string:port);
   port = int(array[1]);
 }
 else
 {
   send(socket:socket, data:'PASV\r\n');
   r = ftp_recv_line(socket:socket);
   if ( r[0] != '2' ) return 0;
   port = egrep(pattern:"^227 .* \(?[0-9]+,[0-9]+,[0-9]+,[0-9]+,[0-9]+,[0-9]+\)?", string:r);
   if ( ! port ) return 0;
   array = eregmatch(pattern:"^227 .* \(?[0-9]+,[0-9]+,[0-9]+,[0-9]+,([0-9]+),([0-9]+)\)?", string:port);
   if ( isnull(array) ) return 0;
   port = int(array[1]) * 256 + int(array[2]);
 }
 return port;
}

function get_ftp_port(default, broken)
{
  local_var	port;

  port = get_kb_item("Services/ftp");
  if (! port) port = default;
  if (! get_port_state(port)) exit(0, strcat('Port ', port, ' is closed.'));
  if (! broken && 
      (get_kb_item('ftp/'+port+'/broken') || 
       get_kb_item('ftp/'+port+'/backdoor'))) exit(0, 'FTP server is broken.');
  return port;
}

function get_ftp_ports(default, broken)
{
  local_var port, ports, unchecked;

  ports = make_list();
  unchecked = get_kb_list("Services/ftp");
  # Nothing found in the KB, use the default
  if(isnull(unchecked) && default)
      unchecked = make_list(default);
  else
      unchecked = make_list(unchecked, default);

  unchecked = list_uniq(unchecked);

  foreach port (unchecked)
  {
    # If the port isn't open, we won't add it to the list
    if(!get_port_state(port))
      continue;

    # If declared broken or backdoored, we won't add it to the list
    else if(!broken &&
            (get_kb_item('ftp/'+port+'/broken') ||
            get_kb_item('ftp/'+port+'/backdoor')))
           continue;
    # All open and not broken or backdoored, we will add it to the list
    else
    {
      if (port)
        ports = make_list(ports, port);
    }
  }

  # Even though we added port 21 if there were no ports found, it
  # could be broken or backdoored, and therefore not added to 'ports'
  if(max_index(ports) == 0)
    return NULL;
  else
    return ports;
}

#----------------------------------------------------------------#
# Function    : ftp_starttls                                     #
# Description : Sends an AUTH TLS command to an open socket.     #
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
# Usage       : if (ftp_starttls(socket:soc, encaps:encaps))     #
#               {                                                #
#                 data = ftp_send_cmd(socket:soc, cmd:...        #
#----------------------------------------------------------------#
function ftp_starttls(socket, dont_read_banner, encaps)
{
  local_var r;

  if (!dont_read_banner)
  {
    r = ftp_recv_line(socket:socket);
    if (!r) return NULL;
  }

  r = ftp_send_cmd(socket:socket, cmd:'AUTH TLS');
  if (strlen(r) < 4) return NULL;

  if (substr(r, 0, 2) != "234") return FALSE;

  if (encaps)
  {
    if (!defined_func("socket_negotiate_ssl")) return NULL;
    return socket_negotiate_ssl(socket:socket, transport:encaps);
  }
  return socket;
}
