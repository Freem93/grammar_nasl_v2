#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
#
# See the Nessus Scripts License for details
#

include("compat.inc");

if (description)
{
 script_id(10783);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2014/05/26 15:30:09 $");

 script_cve_id("CVE-2000-0707");
 script_bugtraq_id(1557);
 script_osvdb_id(653);

 script_name(english:"PCCS-Mysql User/Password Exposure");
 script_summary(english:"Checks for dbconnect.inc");

 script_set_attribute(attribute:"synopsis", value:"Sensitive data may be read on the remote host.");
 script_set_attribute(attribute:"description", value:
"It is possible to read the include file of PCCS-Mysql, dbconnect.inc
on the remote server.

This include file contains information such as the username and
password used to connect to the database.");
 script_set_attribute(attribute:"solution", value:
"Versions 1.2.5 and later are not vulnerable to this issue. A
workaround is to restrict access to the .inc file.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/08/04");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/10/16");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2001-2014 Alert4Web.com");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
res = is_cgi_installed_ka(port:port, item:"/pccsmysqladm/incs/dbconnect.inc");
if( res )security_hole(port);
