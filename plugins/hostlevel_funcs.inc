#TRUSTED 7ef8adf62e02240287cc95a223906bf4f7a5a71d04276e0425a8fcb1f1b78ff90abf535208a77af27436f45c11ab4751869251e4f90c775f9b68db6fda1a2bde6f13a5e0afe894030064fda3f8cb5992b0d0fcff6f8cbfdf0b04fb68db5a8b8bc6b7761a654bd1d73eace7e2926290fa8932cd14d7eb04d11494d1350d8247b8cd0ceeab2cae9175c92407f623a215fcf6b34a79cf59718358da59561bd2985bc038ff32b0399a410fd5f61a97146b62ab87df76ce3952e7044a067ac17c0c328a4137d43f2f809295985f6ed2c4b59d249557864b92b87fbaff462a16f56f93ac56d43a60d57cfea5781dce512295100ce6f62762dbd9e142e8ce65835949ceefc90e650e3f515e203a5c6c39ee66716924afcc6c3d3921e49563a438f751e34ff18cf02e733a214aa6100df21ad12f61387f42fe55cff913b1d77b6856e76ff2f20448044f4a4f19cca67348f9055d33da67b55ba31e2b89854ec44e7ecbcf4344d438051ddd9406189b42d2ccf20ebd39ff0e7469839b56254edf34912585314e8bd086b6347712569b02eb708e10ab4b0fd576be5e2dfe0722257ecb1f3a1da8a5c8ff03444bc4feb61e912fb11edd1bda61e1fe94628163f39e2b5bf04cb2bb57ef2e24bef0811d657c32b58217e5027b91f8c3847bd2401263210e5c1a0c3b1fc0d4462aeba6abecebc1adcd7f484521d2fcdda4a9f4e932d13f9f91d0
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# hostlevel_funcs.inc
#
# Revision: 1.16
#

global_var report_verbosity, port_g, login, pass;
global_var	info_t, sock_g, sep, c;

INFO_LOCAL  = 1;
INFO_SSH    = 2;
INFO_RSH    = 3;
INFO_REXEC  = 4;
INFO_RLOGIN = 5;
INFO_TELNET = 6;

# Error codes
HLF_OK       =  0;  # No error
HLF_MISMATCH = -1;  # Argument no./template mismatch.
HLF_INVALID  = -2;  # Invalid characters in argument(s)
HLF_NO_ARG   = -3;  # An argument is missing.

##
# Open a telnet connection
#
# @param port telnet port
# @param login user to login with
# @param pass password to login with
#
# @return Returns socket if successful, otherwise returns NULL
##
function telnet_open_cnx(port, login, pass)
{
 local_var	s, res;
 local_var	ps;

 if ( ! get_port_state(port) ) return NULL;
 s = open_sock_tcp(port);
 if (! s) return NULL;

 res = telnet_negotiate(socket: s);
 if (strlen(res) == 0)
 {
  close(s);
  return NULL;
 }
 send(socket: s, data: strcat(login, '\r\n'));
 res = recv_until(socket: s, pattern: "[pP]assword:");
 if (strlen(res) == 0)
 {
  close(s);
  return NULL;
 }
 send(socket: s, data: strcat(pass, '\r\n'));

 ps = '([$#%>] )|([a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+ +(/|(/[^/]+)+/*) *[$#%>])';

 res = recv_until(socket: s, pattern: ps);
 if (strlen(res) == 0)
 {
  close(s);
  return NULL;
 }
 send(socket: s, data: 'thisisnotaknowncommand'+rand()+'\r\n');
 res = recv_until(socket: s, pattern: ps);
#debug_print('Bad command => ', res);
 if ('thisisnotaknowncommand' >!< res)
 {
  close(s);
  return NULL;
 }
 return s;
}

##
# Runs command via rexec
#
# @param port rexec port
# @param login user to login with
# @param pass password to login with 
# @param cmd command to run
#
# @returns NULL if error, or string containing command result
##
function send_rexec(port, login, pass, cmd)
{
  local_var	s, buf;

  if ( ! get_port_state(port) ) return NULL;
  s = open_priv_sock_tcp(dport: port);
  if (! s) return NULL;
  send(socket: s, data: '\0');    # No separate channel for error :-(
  send(socket: s, data: strcat(login, '\0', pass, '\0', cmd, '\0'));
  buf = recv(socket: s, length: 1);  # 0 if OK?
  if ( isnull(buf) || ord(buf[0]) > 0)
  {
   close(s);
   return NULL;
  }
  buf = recv(socket: s, length: 1024*1024);
  close(s);
#debug_print('send_rexec: cmd = ', cmd, '\nbuf = \n', buf, '\n\n');
  return buf;
}

##
# Performs rlogin
#
# @param port rlogin port
# @param login username to login with
# @param pass password to login with
# @param from from user (optional, defaults to 'root')
#
# @return socket if successful, NULL if failure
##
function rlogin(port, login, pass, from)
{
 local_var	s, r;

 if ( ! get_port_state(port) ) return NULL;
 s = open_priv_sock_tcp(dport: port);
 if (!s) return NULL;
 if (! from) from = 'root';
 send(socket: s, data: '\0');
 send(socket: s, data: strcat(from, '\0', login, '\0raw/38400\0'));
 r = recv(socket: s, length: 1);
 if (r != '\0') { close(s); return NULL; }
 r = recv(socket: s, length: 1024*1024);
 if (r =~ 'Password *: *$')
 {
  send(socket: s, data: pass + '\r');
  r = recv(socket: s, length: 1024*1024);
  # display("'", ord(r[0]), "' (r)\n");
  if (r =~ 'Password *: *$')
  {
   close(s);
   return NULL;
  }
 }
 return s;
}

##
# Runs command via rsh
# 
# @param port rsh port
# @param login User to login as 
# @param from From user (optional, default is 'root')
# @param cmd Command to run
#
# @return NULL if error or string containing command output
##
function send_rsh(port, login, from, cmd)
{
 local_var	s, buf;

 if (! from) from = 'root';
 s = open_priv_sock_tcp(dport: port);
 if (! s) return NULL;
 send(socket: s, data: '0\0');	# No separate channel for error :-(
 send(socket: s, data: strcat(from, '\0', login, '\0', cmd, '\0'));
 buf = recv(socket: s, length: 1);  # 0 if OK?
 if (ord(buf[0]) > 0)
 {
  close(s);
  return NULL;
 }
 buf = recv(socket: s, length: 1024*1024);
 close(s);
 return buf;
}

##
# Run ssh/telnet/rsh/rexec/local command
#
# @param cmd Command to run
# @param timeout A caller provided timeout (currently SSH only)
# @param nosudo Disables sudo in ssh_cmd
#
# @return NULL if error or result of command as string
##

function info_send_cmd(cmd, timeout, nosudo)
{
 local_var	buf, f;

#debug_print('info_send_cmd: cmd=', cmd);

 if (info_t == INFO_LOCAL)
 {
  if (match(string: cmd, pattern: "cat *") && ">" >!< cmd)
  {
   f = substr(cmd, 4);
   if (! file_stat(f))
   {
#debug_print('info_send_cmd: ', f, ' does not exist or cannot be read\n');
    return NULL;
   }
   else
    return fread(f);
  }
  else
  {
   if ("'" >< cmd) sep = '"';
   else sep = "'";
   return pread(cmd: "/bin/sh", argv: make_list("sh", "-c", cmd));
  }
 }

 if (info_t == INFO_SSH)
 {
  if (isnull(timeout))
  {
    timeout = 120;
  }
  return ssh_cmd(cmd: cmd, timeout: timeout, nosudo: nosudo);
 }

 if (info_t == INFO_RSH)
 {
  return send_rsh(login: login, port: port_g, cmd:cmd);
 }
 if (info_t == INFO_REXEC)
 {
  return send_rexec(login: login, pass: pass, port: port_g, cmd:cmd);
 }

 if (info_t == INFO_TELNET)
 {
  send(socket: sock_g, data:
  # Yes! Two spaces (or more) are necessary
    strcat('echo NESSUS  START; ', cmd, ' 2>/dev/null; echo NESSUS  END\r\n'));
  # But just one space here!
  buf = recv_until(socket: sock_g, pattern: 'NESSUS END');
#debug_print('buf=>>>\n', buf, '<<<\n');
  recv_until(socket: sock_g, pattern: '[%$#>] ');
  # Only one space here!
  buf = strstr(buf, 'NESSUS START');
#debug_print('buf=>>>\n', buf, '<<<\n');
  c = buf - 'NESSUS START';
  while (c[0] == '\r' || c[0] == '\n' || c[0] == ' ' || c[0] == '\t')
   c = substr(c, 1);
  c = chomp(c - 'NESSUS END');
#if (c == buf) debug_print('info_send_cmd: could not extract command output from: ', buf);
#debug_print('c=>>>\n', c, '<<<\n');
  return c;
 }

 #log_print('info_send_cmd: unhandled case info_t=', info_t, ' - cmd=', cmd, '\n');
 return NULL;
}

##
# run a command from a template
# all variables are checked to prevent command injection
#
# @param template : arguments are presented as $<argument_number>$ in template
# @param args : list of arguments (optional)
# @return array s.t. 'data' contains the return value of the command
#               'error' contains the relevant error code.
function run_cmd_template(template, args, exit_on_fail)
{
  local_var i, arg, buf, err;
  i = 1;

  if(isnull(exit_on_fail)) exit_on_fail = FALSE;

  if (isnull(template))
  {
    err = 'run_cmd_template(): missing required arg "template"';
    if(exit_on_fail) exit(1, err);
    return make_array('error', HLF_NO_ARG);
  }

  # we shouldn't have variable in template if no arguments are present
  # coding error, so exit
  if (isnull(args) && ereg(pattern:"\$[0-9]+\$", string:template))
  {
    err = 'run_cmd_template(): Template variables present with no arguments.';
    if(exit_on_fail) exit(1, err);
    return make_array('error', HLF_MISMATCH);
  }

  # sanitize arguments to prevent command injection
  # attacks
  foreach arg (args)
  {
    # only allow whitelisted characters to prevent command injection
    # strings starting with '-' aren't allowed unless surrounded by quotes
    if (arg !~ '^(( *[*A-Za-z0-9_./\\[\\]][*A-Za-z0-9_.\\-/\\[\\]]*)*|'+
               '(\'[*A-Za-z0-9_.\\-/\\[\\] ]*\')|'+
               '("[*A-Za-z0-9_.\\-/\\[\\] ]*"))$')
    {
      err = 'run_cmd_template(): Invalid characters in argument "args"';
      if(exit_on_fail) exit(1, err);
      return make_array('error', HLF_INVALID);
    }
    template = ereg_replace(string:template, pattern:"\$" + i + "\$", replace:arg);
    i++;
  }
  # template variable number / argument number mismatch
  # coding error, so exit
  if (ereg(pattern:"\$[0-9]+\$", string:template))
  {
    err = "run_cmd_template(): The number of template variables mismatch the number of arguments provided.";
    if(exit_on_fail) exit(1, err);
    return make_array('error', HLF_MISMATCH);
  }

  buf = info_send_cmd(cmd:template);

  return make_array('data', buf, 'error', HLF_OK);
}

##
# Sets global variables
##
function set_globals()
{
 local_var opt;
 opt = get_kb_item("global_settings/report_verbosity");

 if (opt )
        {
        if ("Verbose" >< opt ) report_verbosity = 2;
        else if ("Normal" >< opt ) report_verbosity = 1;
        else if ("Quiet" >< opt ) report_verbosity = 0;
        }
}

set_globals();
