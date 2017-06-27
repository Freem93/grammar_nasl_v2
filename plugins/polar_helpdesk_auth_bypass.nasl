#
# (C) Tenable Network Security, Inc.
#

# *UNTESTED*

include("compat.inc");

if(description)
{
 script_id(14193);
 script_cve_id("CVE-2004-2736");
 script_bugtraq_id(10775);
 script_osvdb_id(8168);
 script_version ("$Revision: 1.12 $");
 
 script_name(english: "Polar HelpDesk Authentication Bypass");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to gain administrative rights on a remote web application." );
 script_set_attribute(attribute:"description", value:
"The remote server is running Polar HelpDesk. 

There is a flaw in the remote version of this software that may allow
an attacker to bypass the authentication mechanism of this software and
gain administrative access." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(287);


 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/07/22");
 script_cvs_date("$Date: 2011/08/19 21:24:52 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Checks for Polar HelpDesk");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

foreach d (cgi_dirs())
{
 set_http_cookie(name: "HelpDesk_User", value: "UserType=6&UserID=1");
 r = http_send_recv3(method: "GET", item:d+"/billing/billingmanager_income.asp", port:port);
 if (isnull(r)) exit(0);
 res = r[1]+r[2];
 if( "ticketinfo.asp" >< res &&
   egrep(pattern:"\.\./ticketsupport/ticketinfo\.asp\?ID=[0-9]*", string:res) )
 {
	security_hole(port);
	exit(0);
 }
}
