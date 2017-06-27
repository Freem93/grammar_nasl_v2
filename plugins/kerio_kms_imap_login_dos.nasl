#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21050);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2006-1158");
  script_bugtraq_id(17043);
  script_osvdb_id(23772);

  script_name(english:"Kerio MailServer IMAP Server Crafted LOGIN Command DoS");
  script_summary(english:"Checks how KMS IMAP server responds to login requests");

 script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is prone to denial of service attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Kerio MailServer, a commercial mail server
available for Windows, Linux, and Mac OS X platforms. 

The installed version of Kerio MailServer terminates abnormally when
it receives certain malformed IMAP LOGIN commands.  An unauthenticated,
remote attacker can exploit this issue to deny access to legitimate
users. 

Note that the application may not terminate immediately but only after
an administrator acknowledges a console message." );
  # http://lists.grok.org.uk/pipermail/full-disclosure/2006-March/043567.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c33a56f3" );
 script_set_attribute(attribute:"see_also", value:"http://www.kerio.com/kms_history.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Kerio MailServer 6.1.3 Patch 1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/09");
 script_cvs_date("$Date: 2012/08/16 22:13:12 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:kerio:kerio_mailserver");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2006-2012 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "imap_overflow.nasl");
  script_exclude_keys("imap/false_imap", "imap/overflow");
  script_require_ports("Services/imap", 143);

  exit(0);
}


include("imap_func.inc");


port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port)) exit(0);
if (get_kb_item("imap/"+port+"/false_imap")
 || get_kb_item("imap/"+port+"/overflow")) exit(0);


# Make sure it's a potentially-affected version of Kerio.
banner = get_imap_banner(port:port);
if (!banner) exit(0);

pat = ".*OK Kerio MailServer (.+) IMAP.*";
matches = egrep(pattern:pat, string:banner);
ver = NULL;
if (matches)
{
  foreach match (split(matches))
  {
    match = chomp(match);
    ver = ereg_replace(pattern:pat, replace:"\1", string:match);
    break;
  }
}
if (!ver) exit(0);
iver = split(ver, sep:'.', keep:FALSE);
if (int(iver[0]) > 6) exit(0);
if (int(iver[0]) == 6 && int(iver[1]) > 1) exit(0);
if (int(iver[0]) == 6 && int(iver[1]) == 1 && int(iver[2]) > 3) exit(0);


# Establish a connection.
tag = 0;
soc = open_sock_tcp(port);
if (!soc) exit(0);


# Read banner.
s = recv_line(socket:soc, length:1024);
if (!strlen(s))
{
  close(soc);
  exit(0);
}


# Send a login command.
c = "a001 LOGIN {999999}";
send(socket:soc, data:string(c, "\r\n"));
s = recv_line(socket:soc, length:1024);


# NB: a patched server responds "+ Go ahead";
#     an unpatched one, "a001 BAD LOGIN Missing user name";
if (strlen(s) && "BAD LOGIN Missing user name" >< s) 
{
  security_hole(port);
}
close(soc);
