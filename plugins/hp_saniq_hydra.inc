#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# $Revision: 2.2 $
#

### Packet / Message Types ###
global_var HP_HYDRA_TYPE_CMD;
HP_HYDRA_TYPE_CMD = '\x14';
global_var HP_HYDRA_TYPE_LOCALE;
HP_HYDRA_TYPE_LOCALE = '\x16';
global_var HP_HYDRA_TYPE_TRANSFORMS; 
HP_HYDRA_TYPE_TRANSFORMS = '\x10';

global_var _hp_hydra_login;
_hp_hydra_login = 0;

### Login Responses ###
global_var HP_HYDRA_LOGIN_OK;
HP_HYDRA_LOGIN_OK = _hp_hydra_login++;
global_var HP_HYDRA_LOGIN_BAD_CREDS;
HP_HYDRA_LOGIN_BAD_CREDS = _hp_hydra_login++;
global_var HP_HYDRA_LOGIN_CLIENT_TOO_OLD;
HP_HYDRA_LOGIN_CLIENT_TOO_OLD = _hp_hydra_login++;

##
# Creates a Hydra packet
#
# @param type Packet Type (use a HP_HYDRA_TYPE_* global to specify)
# @param cmd  command / packet payload
# @param port port
# @param term NULL terminate payload/command if TRUE
# @return Returns packet ready to send. 
##
function hp_hydra_create_packet(type, cmd, port, term)
{
  local_var pkt;

  # required arguments
  if(isnull(type)) exit(1, "A NULL type argument was passed to hp_hydra_create_packet()");
  if(isnull(cmd)) exit(1, "A NULL cmd argument was passed to hp_hydra_create_packet()");
  if(isnull(port)) exit(1, "A NULL port argument was passed to hp_hydra_create_packet()");

  if(isnull(term))
  {
    term = get_kb_item("HYDRA_SANIQ/" + port + "/Terminate_Commands");
    if(isnull(term)) term = FALSE;
  }

  if(term)
    cmd += '\x00';

  pkt = '\x00\x00\x00\x00\x00\x00\x00\x01' +
        mkdword(strlen(cmd)) +
        '\x00\x00\x00\x00' + 
        '\x00\x00\x00\x00\x00\x00\x00\x00' + 
        '\x00\x00\x00' + type + '\xff\xff\xff\xff' +
        cmd;

  return pkt;
}

##
# Sends / Receives Hydra packets
#
# @param socket TCP socket
# @param request request packet
# @param port port
# @param exit_on_fail if TRUE, exit if there is a protocol error
# @return Returns server response or NULL on error
##
function hp_hydra_send_recv(socket, request, port, exit_on_fail)
{
  local_var header, len, data;

  # required arguments
  if(isnull(socket)) exit(1, "A NULL socket argument was passed to hp_hydra_send_recv()");
  if(isnull(port)) exit(1, "A NULL port argument was passed to hp_hydra_send_recv()");
  if(isnull(request)) exit(1, "A NULL request argument was passed to hp_hydra_send_recv()");

  if(isnull(exit_on_fail)) exit_on_fail = FALSE;

  send(socket:socket, data:request);
  header = recv(socket:socket, length:32, min:32);

  if(strlen(header) != 32 || header == '' || isnull(header))
  {
    if(exit_on_fail)
    {
      close(socket);
      audit(AUDIT_RESP_BAD, port);
    }
    else return NULL;
  }

  len = getdword(blob:header, pos:8);
  
  # sanity check
  if (len >= 10*1024*1024)
  {
    if(exit_on_fail)
    {
      close(socket);
      audit(AUDIT_RESP_BAD, port, 'request (length over 10 megs)');
    }
    else return NULL;
  }

  data = recv(socket:socket, min:len, length:len);
  if(strlen(data) != len)
  {
    if(exit_on_fail)
    {
      close(socket);
      audit(AUDIT_RESP_BAD, port, 'request (unexpected length)');
    }
    else return NULL;
  }

  return data;
}

##
# Run commands (HP_HYDRA_TYPE_CMD) on post login
#
# @param socket TCP socket
# @param port port
# @param cmd command string to run
# @param term NULL terminate payload/command if TRUE
# @param exit_on_fail if TRUE, exit if there is a protocol error
# @return Returns server response or NULL on error
##
function hp_hydra_run_command(socket, port, cmd, term, exit_on_fail)
{
  local_var pkt, res;

  # required arguments
  if(isnull(socket)) exit(1, "A NULL socket argument was passed to hp_hydra_run_command()");
  if(isnull(port)) exit(1, "A NULL port argument was passed to hp_hydra_run_command()");
  if(isnull(cmd)) exit(1, "A NULL cmd argument was passed to hp_hydra_run_command()");

  pkt = hp_hydra_create_packet(type: HP_HYDRA_TYPE_CMD, cmd:cmd, port:port, term:term);
  res = hp_hydra_send_recv(socket:socket, port:port, request:pkt, exit_on_fail:exit_on_fail);

  if(isnull(res)) return NULL;

  # retry command with NULL termination if error response indicates that we should
  if(res =~ '^ERR *: *Non terminated key')
  {
    set_kb_item(name:"HYDRA_SANIQ/" + port + "/Terminate_Commands", value:TRUE);
    pkt = hp_hydra_create_packet(type: HP_HYDRA_TYPE_CMD, cmd:cmd, port:port, term:TRUE);
    res = hp_hydra_send_recv(socket:socket, port:port, request:pkt, exit_on_fail:exit_on_fail);
  }

  return res;
}

##
# Used to determine if a given version of remote host is <= supplied
# vulnerable version.
#
# This is done by sending a login request with supplied version and
# examining response to see if the device accepts logins for the version. 
#
# @param socket TCP socket
# @param port port
# @param vuln_version greatest vulnerable version less than fix
# @param exit_on_fail if TRUE, exit if there is a protocol error
#
# @return Returns TRUE if device accepts logins for given version 
#
# @remark Since this function attempts a login with random credentials, it will return NULL unless supplied_logins_only is set
##
function hp_hydra_is_vuln(socket, port, vuln_version, exit_on_fail)
{
  local_var login_res;

  # argument checking
  if(isnull(socket)) exit(1, "A NULL socket argument was passed to hp_hydra_is_vuln()");
  if(isnull(port)) exit(1, "A NULL port argument was passed to hp_hydra_is_vuln()");
  if(isnull(vuln_version)) exit(1, "A NULL vuln_version argument was passed to hp_hydra_is_vuln()");

  # we can only use this function to test if supplied_logins_only is set
  if(supplied_logins_only) return NULL;

  login_res = hp_hydra_login(socket:socket,
                             port:port,
                             version:vuln_version,
                             exit_on_fail:exit_on_fail);

  if(login_res == HP_HYDRA_LOGIN_BAD_CREDS ||
     login_res == HP_HYDRA_LOGIN_OK)
    return TRUE;
  else return FALSE;
}

##
# Tries to login 
#
# @param socket TCP socket
# @param port port
# @param username username (defaults to random string) 
# @param password password (defaults to random string)
# @param version version (defaults to 100.0)
# @param term NULL terminate payload/command if TRUE
# @param exit_on_fail if TRUE, exit if there is a protocol error
#
# @return Returns login status (see HP_HYDRA_LOGIN_* globals) or
# NULL on unhandled response
##
function hp_hydra_login(socket, port, username, password, version, term, exit_on_fail)
{
  local_var login, res;

  # required arguments
  if(isnull(socket)) exit(1, "A NULL socket argument was passed to hp_hydra_login()");
  if(isnull(port)) exit(1, "A NULL port argument was passed to hp_hydra_login()");

  # with unmanaged devices, they will accept any set of credentials
  if(isnull(username)) username = rand_str();
  if(isnull(password)) password = rand_str();

  # really high version number that should allow us to login to any version
  if(isnull(version)) version = "100.0";

  login = 'login:/' + username + '/' + password + 
          '/Version "' + version + '"';   

  res = hp_hydra_run_command(socket:socket, port:port, cmd:login, term:term, exit_on_fail:exit_on_fail);
  
  if(res =~ '^OK *: *Login')
    return HP_HYDRA_LOGIN_OK;
  else if('user name or password is invalid' >< res)
    return HP_HYDRA_LOGIN_BAD_CREDS;
  else if(res =~ 'The version of the (SAN/iQ|Lefthand OS) client is too old')
    return HP_HYDRA_LOGIN_CLIENT_TOO_OLD;
  else return NULL;
}

