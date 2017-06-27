#
# (C) Tenable Network Security, Inc.
#

# *untested*
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#

include("compat.inc");

if (description)
{
 script_id(11064);
 script_version("$Revision: 1.32 $");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");

 script_cve_id("CVE-2002-1021");
 script_bugtraq_id(5226);
 script_osvdb_id(8610);

 script_name(english:"BadBlue Hex-encoded Null Byte Request Arbitrary File Access");
 script_summary(english:"Read BadBlue protected configuration file");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host is running the BadBlue web server. It was possible to
read the contents of 'EXT.ini', the BadBlue configuration file, by
sending a specially crafted GET request.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Jul/143");
 script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/06/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/06");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencies("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
if ("BadBlue" >!< banner ) exit(0);


r = string("/ext.ini.%00.txt");
res = is_cgi_installed3(item:r, port:port);
if( res ) security_warning(port);
