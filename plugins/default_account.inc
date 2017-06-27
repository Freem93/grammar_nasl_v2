# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# This file implements (or will implement) various ways of determining if
# an account is valid
#
# @NOGPL@
#
# default_account.inc
# Revision: 1.35
#

include('telnet_func.inc');
include('ssh_func.inc');


global_var _login_text;
#
# Private functions
#

function default_account_report(cmd)
{
 local_var retval;
 if(isnull(cmd))
 {
   if("uid=" >< _login_text)
     cmd = 'id'; 
 }

 if ( isnull(_login_text) || strlen(_login_text) == 0 ) return NULL;
 if (!isnull(cmd))
 {
  retval = '\n' + "It was possible to execute the command '" + cmd + "' on the remote host :" +
           '\n\n';

  # don't add formatting spaces for multi-line command output
  if('\n' >< chomp(_login_text))
    retval += _login_text;
  else retval += '  ' + _login_text;

  return retval; 

 }
 else return '\n' + "Once logged in, we obtained the following :" +
             '\n' +
             '\n' + _login_text;
}

function _check_telnet(port, login, password, login_regex, password_regex, cmd, cmd_regex, out_regex_group)
{
 local_var soc, res, res2, ch, item;
 soc = open_sock_tcp(port);
 if(!soc)return(0);

 if(!isnull(cmd))
 {
   if(isnull(cmd_regex))
     exit(1, 'Missing required cmd_regex argument.');
 }

 res = telnet_negotiate(socket:soc);

 if(!isnull(login))
 {
   if (isnull(login_regex)) login_regex = "ogin:";

   res += recv_until(socket:soc, pattern:login_regex);
   if ( ! res ) exit(0, 'A login prompt was not found while connecting to port '+port+'.');
   
   res = '';
   send(socket:soc, data:login + '\r\n');
 }

 if (isnull(password_regex)) password_regex = "word[ ]*[:>]";
 res += recv_until(socket:soc, pattern:password_regex);

 if (res)
 {
   # nb: NULL is not the same as an empty password, and a 
   #     Telnet server may display a password prompt even
   #     when the account has an empty password.
   if (isnull(password)) 
   {
     close(soc);
     return 0;
   }
   send(socket:soc, data:password+'\r\n');
 }
 else
 {
   # nb: If there was no password prompt but the check
   #     includes a password, it's a failure.
   if (strlen(password))
   {
     close(soc);
     return 0;
   }
 }

 # nb: Some servers prompt for a terminal type.
 res = recv_until(socket:soc, pattern:'Terminal type\\?');
 if (res)
 {
   if ('Terminal type?' >< res) send(socket:soc, data:'vt100\r\n');
 }

 if(!isnull(cmd))
   send(socket:soc, data:cmd +'\r\n');
 else
   send(socket:soc, data:'id\r\n');

 if(!isnull(cmd))
 { 
   ch = recv(socket:soc, length:1);
   while(strlen(ch) != 0)
   {
     res += ch;
     ch = recv(socket:soc, length:1);
    
     if(res =~ cmd_regex)
     {
       if(isnull(out_regex_group))
       {
         _login_text = res;
       }
       else
       {
         item = eregmatch(pattern:cmd_regex, string:res);
         _login_text = item[out_regex_group];
       }
       close(soc);
       return 1;
     }
   }
 }
 else
 {
   res += recv_until(socket:soc, pattern:"uid=");
   if ("uid=" >< res)
   {
     res2 = recv_until(socket:soc, pattern:'gid.+\\r');
     if (res2)
     {
       res = "uid=" + chomp(res2);
       _login_text = res;
     }
     close(soc);
     return 1;
   }
 }
 close(soc);
 return 0;
}

#-------------------------------------------------------------------#

function check_account(login, password, unix, check_mocana, cmd, cmd_regex, out_regex_group, nosh, nosudo, noexec, nosetup, check_telnet)
{
 local_var port, ret, banner, soc, res, item;
 local_var payload, remote_channel;

 if (  get_kb_item("global_settings/supplied_logins_only") ) return 0;
 if ( isnull(unix) || unix == TRUE )
 {
   if (  get_kb_item("login/unix/auth/broken") ) return 0;
 }
 else if (  get_kb_item("login/auth/broken") ) return 0;
 

 if ( defined_func("bn_random") )
 {
  # Prefer login thru SSH rather than telnet
  port = get_kb_item("Services/ssh");
  if ( ! port ) port = 22;

  banner = get_kb_item("SSH/banner/" + port);
  if (!banner)
  {
    banner = get_kb_item("ssh/banner/" + port);
    if (banner) banner = chomp(banner);
  }

  if (
    banner && 
    # GoodTech SSH server does not respect SSH protocol ...
    "cryptlib" >!< banner && 
    # nor does Mocana's (at least as used in AMX devices).
    ("SSH-2.0-Mocana SSH" >!< banner || check_mocana == TRUE)
  ) 
  {
   _ssh_socket = open_sock_tcp(port);
   if ( _ssh_socket )
   {
   ret = ssh_login(login:login, password:password);
   if ( ret == 0 )
   {
    if ( isnull(unix) || unix == TRUE || !isnull(cmd) )
    {
      if(!isnull(cmd))
      {
        if(isnull(cmd_regex))
        exit(1, 'Missing required cmd_regex argument.');
      }

      # Preserve current way of running commands.
      if (isnull(nosh)) nosh = TRUE;
      if (isnull(nosudo)) nosudo = TRUE;

      if(!isnull(cmd))
        ret = ssh_cmd(cmd:cmd, nosh:nosh, nosudo:nosudo, noexec:noexec, nosetup:nosetup);
      else
        ret = ssh_cmd(cmd:'id', nosh:nosh, nosudo:nosudo, noexec:noexec, nosetup:nosetup);

      if(!isnull(cmd))
      { 
        if(ret =~ cmd_regex)
        {
          if(isnull(out_regex_group))
          {
            _login_text = ret;
          }
          else
          {
            item = eregmatch(pattern:cmd_regex, string:ret);
            _login_text = item[out_regex_group];
          }
          ssh_close_connection();
          return port;
        }
      } 
      else
      { 
        if ( ret && "uid=" >< ret )
        {
          ssh_close_connection();
          _login_text = ret;
          return port;
        }
      }
      return 0;
    }

    #
    # Some SSH servers do not fully respect the SSH protocol - they
    # claim that password authentication succeeded, but then 
    # they'll refuse any other command. The workaround here is to
    # open a SSH, as if we wanted to create an interactive session.
    #
    # Note that we do not use ssh_open_channel() but a stripped down version
    #
    payload = putstring(buffer:"session") + raw_int32(i:1) + raw_int32(i:32768) + raw_int32(i:32768);
    send_ssh_packet(payload:payload, code:raw_int8(i:90));
    payload = recv_ssh_packet();
    if ( !isnull(payload) )
    {
	# Fix for tectia AIX
	if (ord(payload[0]) == 95)
 	{
   	 payload = getstring(buffer:payload, pos:9);
      	 payload = recv_ssh_packet();
	}
	if ( !isnull(payload) && ord(payload[0]) == 91 )
	{
	 remote_channel = ntol(buffer:payload, begin:5);
	 payload = raw_int32(i:remote_channel) + putstring(buffer:"pty-req") + raw_int8(i:0) +
         putstring(buffer:"vt100") + raw_int32(i:80) + raw_int32(i:24) + raw_int32(i:640) + raw_int32(i:480) +
         putstring(buffer:
                             raw_int8(i:53) + raw_int32(i:0) +
                             raw_int8(i:72) + raw_int32(i:0) +
                             raw_int8(i:0));

         # SSH_MSG_CHANNEL_REQUEST == 98
         send_ssh_packet(payload:payload, code:raw_int8(i:98));
         payload = raw_int32(i:remote_channel) + putstring(buffer:"shell") + raw_int8(i:0) ;
	 # SSH_MSG_CHANNEL_REQUEST == 98
         send_ssh_packet(payload:payload, code:raw_int8(i:98));
	 payload = raw_int32(i:remote_channel) + putstring(buffer:'\n');
         send_ssh_packet(payload:payload, code:raw_int8(i:94));
	 payload = recv_ssh_packet();

         while(!isnull(payload) && ((ord(payload[0]) == 93) || (ord(payload[0]) == 95) || (ord(payload[0])  == 98)))   payload = recv_ssh_packet();
	 if ( ord(payload[0]) == 94 )
	  {
	   payload = getstring(buffer:payload, pos:5);
	   _login_text = payload;
           if (
             "Domain (? for all)" >!< payload && 
             "invalid login" >!< payload &&
	     ("ogin:" >!< payload || "Last login: " >< payload) && 
             "User Name:" >!< payload &&
             "assword:" >!< payload
           )  
	   {
   	    ssh_close_connection();
	    return port;
 	   }
          }
	}
     }
   }
   ssh_close_connection();
  
   if(isnull(check_telnet)) check_telnet = FALSE;
 
   # nb: under certain conditions, we'll also check any
   #     Telnet service :
   #
   #     - 'login' is root, since SSH might reject root
   #       logins.
   #     - 'password' is empty, since SSH might reject
   #       login attempts if it is (eg, see OpenSSH's
   #       'PermitEmptyPasswords' configuration option)
   #     - thorough tests are enabled.
   #     - check_telnet is set
   if (
     !check_telnet &&
     login != "root" && 
     password && 
     (
       !get_kb_item("global_settings/thorough_tests") ||
       get_kb_item("global_settings/thorough_tests") != "yes"
     )
   ) return 0; 
   }
  }
 }
 if ( (!isnull(unix) && unix == FALSE) && isnull(cmd) ) return 0;
 
port = get_kb_item("Services/telnet");
 if(!port) port = 23;
 
 if(get_port_state(port))
 {
  if ( isnull(password) ) password = "";
  res = _check_telnet(port:port, login:login, password:password, cmd:cmd, cmd_regex:cmd_regex, out_regex_group:out_regex_group);
  if(res)
   return(port);
 }
 return(0);
}
