#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24876);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/06/03 21:40:31 $");

  script_cve_id("CVE-2006-6026");
  script_bugtraq_id(21141, 23068);
  script_osvdb_id(30466);

  script_name(english:"RealNetworks Helix Servers DESCRIBE Request LoadTestPassword Field Remote Overflow");
  script_summary(english:"Checks Helix server banner");

 script_set_attribute(attribute:"synopsis", value:
"The remote RTSP server suffers from a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Helix DNA Server or Helix Server, a media
streaming server. 

The version of the Helix server installed on the remote host contains
a heap overflow involving an invalid 'LoadTestPassword' field.  An
unauthenticated, remote attacker can leverage this flaw using a simple
'DESCRIBE' request to crash the affected application and possibly to
execute arbitrary code subject to the privileges of the user id under
which it runs, which by default on Windows is LOCAL SYSTEM." );
 # http://web.archive.org/web/20070328181828/http://gleg.net/helix.txt
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6449002c" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/463333/30/0/threaded" );
 # http://lists.helixcommunity.org/pipermail/server-cvs/2007-January/003783.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27db559a" );
 script_set_attribute(attribute:"see_also", value:"http://docs.real.com/docs/security/SecurityUpdate032107Server.pdf" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Helix Server / Helix DNA Server version 11.1.3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/03/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/05/02");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/rtsp", 554);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_kb_item("Services/rstp");
if (!port) port = 554;
if (!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);


# Grab the banner.
req = 'OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n';
send(socket:soc, data:req);
r = http_recv3(socket:soc);
close(soc);
if (isnull(r)) exit(0);


h = parse_http_headers(status_line: r[0], headers: r[1]);
# Pull out the server information.
server = h["server"];
if (!server) server = h["via"];
if (!server) exit(0, "No server info");

# If it's Helix Server / Helix DNA Server...
if (
  stridx(server, "Helix Server Version") == 0 || 
  stridx(server, "Helix DNA Server Version") == 0
)
{
  ver = ereg_replace(pattern:"^.+Version ([0-9\.][^ ]+) .+$", replace:"\1", string:server);
  if (ver && ver =~ "^([0-9]\.|10\.|11\.(0\.|1\.[0-2]\.))")
    security_hole(port);
}
