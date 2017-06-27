#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21139);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/01/25 01:19:08 $");

  script_cve_id("CVE-2006-1792");
  script_osvdb_id(30583);

  script_name(english:"MailEnable POP3 Server APOP Command Remote Buffer Overflow");
  script_summary(english:"Tries to crash MailEnable POP3 Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote POP3 server is affected by a buffer overflow flaw." );
  script_set_attribute(attribute:"description", value:
"The remote host is running MailEnable, a commercial mail server for
Windows. 

The POP3 server bundled with the version of MailEnable on the remote
host has a buffer overflow flaw involving the APOP command that can be
exploited remotely by an unauthenticated attacker to crash the
affected service and possibly to execute code remotely." );
  script_set_attribute(attribute:"see_also", value:"http://forum.mailenable.com/viewtopic.php?t=9845" );
  script_set_attribute(attribute:"see_also", value:"http://www.mailenable.com/hotfix/default.asp" );
  script_set_attribute(attribute:"solution", value:
"Apply the ME-10012 hotfix or upgrade to MailEnable Standard Edition
1.94 / Professional Edition 1.74 / Enterprise Edition 1.22 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/23");
  script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/23");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mailenable:mailenable");
  script_end_attributes();
 
  script_category(ACT_ATTACK);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
  script_dependencies("find_service_3digits.nasl", "doublecheck_std_services.nasl");
  script_require_ports("Services/pop3", 110);

  exit(0);
}


include("pop3_func.inc");


port = get_kb_item("Services/pop3");
if (!port) port = 110;
if (!get_port_state(port)) exit(0);


# Make sure banner's from MailEnable.
banner = get_pop3_banner(port:port);
if (!banner || "MailEnable POP3 Server" >!< banner) exit(0);


# Establish a connection
soc = open_sock_tcp(port);
if (!soc) exit(0);


# Make sure APOP is enabled.
s = recv_line(socket:soc, length:1024);
if (strlen(s) && egrep(pattern:"^\+OK .+ MailEnable POP3 Server <.+>", string:s))
{
  # Send a long APOP command - the fix limits the length of the name to 0x4f 
  # so see what happens if we exceed it.
  c = raw_string("APOP ", crap(0x50), " 056924d6c559cca2c64c2a38b030a588\r\n");
  send(socket:soc, data:c);
  s = recv_line(socket:soc, length:1024);

  # Patched / newer versions report "-ERR Bad argument".
  if ("-ERR Unable to log on" >< s) security_hole(port);
}
close(soc);
