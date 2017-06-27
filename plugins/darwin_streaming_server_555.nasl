#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25214);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/06/01 17:55:33 $");

  script_cve_id("CVE-2007-0748", "CVE-2007-0749");
  script_bugtraq_id(23918);
  script_osvdb_id(35975, 35976);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2007-05-10");

  script_name(english:"Darwin Streaming Server < 5.5.5 Multiple RCE Vulnerabilities");
  script_summary(english:"Checks the RTSP server banner.");

 script_set_attribute(attribute:"synopsis", value:
"The remote RTSP server is affected by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apple Darwin Streaming Server
running on the remote host is prior to version 5.5.5. It is,
therefore, affected by multiple vulnerabilities :

  - A heap buffer overflow condition exists in the Apple
    Darwin Streaming Proxy that allows an unauthenticated,
    remote attacker, via multiple trackID values in a
    SETUP RTSP request, to cause application termination
    or the execution arbitrary code.
    (CVE-2007-0748)

  - Multiple stack-based buffer overflow conditions exist
    in the is_command() function within file proxy.c due
    to improper bounds checking. An unauthenticated, remote
    attacker can exploit these, via a long command or server
    value in an RTSP request, to cause application
    termination or the execution arbitrary code.
    (CVE-2007-0749)");
# http://lists.apple.com/archives/Security-announce/2007/May/msg00002.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f8f2e02");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/468303");
  script_set_attribute(attribute:"see_also", value:"http://dss.macosforge.org/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Darwin Streaming Server version 5.5.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value: "2007/05/10");
  script_set_attribute(attribute:"patch_publication_date", value: "2007/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value: "2007/05/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:darwin_streaming_server");
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
include("audit.inc");


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

# If it's Darwin Streaming Server...
if (stridx(server, "DSS/") == 0)
{
  ver = NULL;
  if (server =~ "^DSS/([0-9\.]+) .+$")
    ver = ereg_replace(pattern:"^DSS/([0-9\.]+) .+$", replace:"\1", string:server);
  if (server =~ "^DSS/([0-9\.]+)(\-[^ ]+) .+$")
    ver = ereg_replace(pattern:"^DSS/([0-9\.]+)(\-[^ ]+) .+$", replace:"\1\2", string:server);
  if (!empty_or_null(ver) && ver !~ "^DSS/")
  {
    iver = split (ver, sep:".", keep:FALSE);
    for (i=0; i<max_index(iver); i++)
      if (iver[i] =~ "^\d$") iver[i] = int(iver[i]);

    # Versions before 5.5.5 are affected.
    if (
      iver[0] < 5 ||
      (
        iver[0] == 5 &&
        (
          iver[1] < 5 ||
          (iver[1] == 5 && iver[2] < 5)
        )
      )
    ) 
    {
     report = strcat('Darwin Streaming Server version ', ver, 
     	' appears to be running on the\n',
        'remote host based on the following banner :\n\n',
        '  ', server, '\n' );
      security_report_v4(severity: SECURITY_HOLE, port: port, extra: report);
    } else audit(AUDIT_INST_VER_NOT_VULN, "Darwin Streaming Server", ver);
  } else audit(AUDIT_UNKNOWN_APP_VER, "Darwin Streaming Server");
} else audit(AUDIT_NO_BANNER, port);
