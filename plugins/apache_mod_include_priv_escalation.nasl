#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15554);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2015/08/04 20:57:14 $");

 script_cve_id("CVE-2004-0940");
 script_bugtraq_id(11471);
 script_osvdb_id(11003, 12881);
 script_xref(name:"RHSA", value:"2005:816");
 script_xref(name:"Secunia", value:"12898");
 script_xref(name:"Secunia", value:"19073");

 script_name(english:"Apache mod_include get_tag() Function Local Overflow");
 script_summary(english:"Checks for version of Apache");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a local buffer overflow
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote web server appears to be running a version of Apache that
is older than version 1.3.33.

This version is vulnerable to a local buffer overflow in the get_tag()
function of the module 'mod_include' when a specially crafted document
with malformed server-side includes is requested though an HTTP
session.

Successful exploitation can lead to execution of arbitrary code with
escalated privileges, but requires that server-side includes (SSI) is
enabled.");
 script_set_attribute(attribute:"solution", value:"Upgrade to Apache 1.3.33 or later.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/21");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/25");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("http_version.nasl", "os_fingerprint.nasl", "macosx_SecUpd20041202.nasl");
 script_require_keys("www/apache", "Settings/ParanoidReport");   
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("http_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if ( get_kb_item("CVE-2004-0940") ) exit(0);

port = get_http_port(default:80);
if(!port)exit(0);
if(!get_port_state(port))exit(0);

banner = get_backport_banner(banner:get_http_banner(port: port));
if(!banner)exit(0);

serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/(1\.([0-2]\.|3\.([0-9][^0-9]|[0-2][0-9]|3[0-2])))", string:serv))
 {
   security_warning(port);
   exit(0);
 }
