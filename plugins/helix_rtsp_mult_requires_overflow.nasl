#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25950);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/11/18 20:40:52 $");

  script_cve_id("CVE-2007-4561");
  script_bugtraq_id(25440);
  script_osvdb_id(39903);

  script_name(english:"RealNetworks Helix DNA Server RTSP Service Crafted Require Header Remote Overflow");
  script_summary(english:"Checks Helix server banner");

  script_set_attribute(attribute:"synopsis", value:
"The remote RTSP server is prone to a buffer overflow attack." );
  script_set_attribute(attribute:"description", value:
"The remote host is running Helix Server or Helix DNA Server, a media
streaming server. 

The version of the Helix server installed on the remote host
reportedly contains a heap overflow that is triggered using an RTSP
command with multiple 'Require' headers.  An unauthenticated, remote
attacker can leverage this flaw to execute arbitrary code subject to
the privileges under which it operates, by default LOCAL SYSTEM on
Windows." );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dabedd30" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Aug/432" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Helix Server / Helix DNA Server version 11.1.4 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 119);
  script_set_attribute(attribute:"plugin_publication_date", value: "2007/08/28");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
  if (ver)
  {
    iver = split(ver, sep:'.', keep:FALSE);
    for (i=0; i<max_index(iver); i++)
      iver[i] = int(iver[i]);

    fix = split("11.1.4.0", sep:'.', keep:FALSE);
    for (i=0; i<max_index(fix); i++)
      fix[i] = int(fix[i]);

    for (i=0; i<max_index(iver); i++)
      if ((iver[i] < fix[i]))
      {
        prod = server - strstr(server, " Version");

        report = strcat(
          'According to its banner, the remote host is running ', prod, '\n',
          'version ', ver, "." );
        security_hole(port:port, extra:report);
        break;
      }
      else if (iver[i] > fix[i])
        break;
  }
}
