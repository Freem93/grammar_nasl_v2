#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25402);
 script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2016/05/05 16:01:15 $");

 script_cve_id("CVE-2007-2964");
 script_bugtraq_id(24233);
 script_osvdb_id(36723);

 script_name(english:"F-Secure Policy Manager Server fsmsh.dll module DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is an F-Secure Policy Manager Server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version a F-Secure Policy Manager Server
that is vulnerable to a denial of service. 

A malicious user can forge a request to query a MS-DOS device name
through the 'fsmsh.dll' CGI module, which will prevent legitimate
users from accessing the service using the Manager Console." );
 script_set_attribute(attribute:"see_also", value:"http://www.f-secure.com/en/web/labs_global/fsc-2007-4" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to F-Secure Policy Manager Server 7.01 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/05/29");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:f-secure:policy_manager");

 script_end_attributes();

 script_summary(english:"Detects F-Secure Policy Manager DoS flaw");

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
 script_family(english:"Denial of Service");

 script_dependencies("http_version.nasl", "os_fingerprint.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

os = get_kb_item("Host/OS/icmp");
if (!os || "Windows" >!< os) exit(0);

port = get_http_port(default:80);
if (!port) exit(0);
if(!get_port_state(port))exit(0);

# only check FSMSH.DLL version
buf = http_get(item:"/fsms/fsmsh.dll?FSMSCommand=GetVersion", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);

if (r =~ "^([0-6]\.|7\.00)") security_warning(port);
