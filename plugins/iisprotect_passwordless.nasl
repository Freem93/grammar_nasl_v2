#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11661);
 script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2013/01/25 01:19:08 $");
 
 script_name(english:"iisPROTECT Unpassworded Administrative Interface");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running an application with no password." );
 script_set_attribute(attribute:"description", value:
"The remote host is running iisprotect, an IIS add-on to protect the
pages served by this server.

However, the administration module of this interface has not been
password protected. As a result, an attacker may perform 
administrative tasks without any authentication." );
 script_set_attribute(attribute:"solution", value:
"Set a strong password for accessing this page." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/28");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_summary(english:"Determines if iisprotect is password-protected");

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2013 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/ASP");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

res = http_send_recv3(method:"GET",item:"/iisprotect/admin/GlobalAdmin.asp?V_FirstTab=GlobalSetting", port:port);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

if ("<form action='/iisprotect/admin/GlobalAdmin.asp' method='POST'" >< res[2]) security_hole(port:port);
