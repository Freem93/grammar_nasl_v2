#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added CAN.  Added link to the Bugtraq message archive

include("compat.inc");

if (description)
{
 script_id(10968);
 script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2016/11/23 20:42:23 $");

 script_osvdb_id(53949);

 script_name(english:"ping.asp CGI Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of ping.asp");

 script_set_attribute(attribute:"synopsis", value:"A CGI could be used to launch denial of service attacks.");
 script_set_attribute(attribute:"description", value:
"The 'ping.asp' CGI is installed. Some versions allow an attacker to
launch a ping flood against the targeted machine or another by
entering '127.0.0.1 -l 65000 -t' in the Address field.");
 script_set_attribute(attribute:"solution", value:"Remove it.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
 # https://web.archive.org/web/20080705143950/http://archives.neohapsis.com/archives/ntbugtraq/2002-q2/0125.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8331f8d5");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/06/02");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl", "webmirror.nasl");
 script_require_keys("Settings/ParanoidReport", "www/ASP");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

if (is_cgi_installed3(port:port, item:"ping.asp"))
{
 security_hole(port);
 exit(0);
}

if (is_cgi_installed3(port:port, item:"/ping.asp"))
{
 security_hole(port);
 exit(0);
}
