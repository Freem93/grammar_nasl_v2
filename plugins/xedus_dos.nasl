#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14646);
  script_version("$Revision: 1.22 $");

  script_cve_id("CVE-2004-1644");
  script_bugtraq_id(11071);
  script_osvdb_id(9387);
  script_xref(name:"Secunia", value:"12418");

  script_name(english:"Xedus Webserver Connection Saturation DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web server with a denial of
service vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host runs Xedus Peer-to-Peer web server.  This version
is vulnerable to a denial of service. An attacker could stop the
web server from accepting user requests by establishing multiple
connections from the same host." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?beb4bd71" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:U/RC:X");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/30");
 script_cvs_date("$Date: 2017/02/07 14:52:10 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_summary(english:"Checks for denial of service in Xedus");
  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2004-2017 Tenable Network Security, Inc.");
  script_dependencies("xedus_detect.nasl");
  script_family(english:"Peer-To-Peer File Sharing");
  script_require_ports("Services/www", 4274);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");

port = get_http_port(default:4274);
if ( ! get_kb_item("xedus/" + port + "/running")) exit(0);

if (! get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);


  soc = open_sock_tcp(port);
  if (! soc) audit(AUDIT_SOCK_FAIL, port);

  s[0] = soc;

  for (i = 1; i < 50; i = i+1)
  {
    soc = open_sock_tcp(port);
    if (! soc)
    {
      if (service_is_dead(port: port) > 0)
        security_warning(port);
      break;
    }
    sleep(1);
    s[i] = soc;
  }

  for (j = 0; j < i; j=j+1) close(s[j]);
