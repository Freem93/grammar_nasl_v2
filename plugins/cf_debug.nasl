#
# This script was written by Felix Huber <huberfelix@webtopia.de>
#
# v. 1.06 (last update 07.11.01)


include("compat.inc");

if(description)
{
 script_id(10797);
 script_version ("$Revision: 1.24 $");
 script_osvdb_id(15301);

 script_name(english:"ColdFusion Debug Mode Information Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected
by an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"It is possible to see the ColdFusion Debug Information by appending 
'?Mode=debug' at the end of the request.

ColdFusion 4.5 and 5.0 are definitely concerned (probably in
addition older versions).

The Debug Information usually contain sensitive data such
as Template Path or Server Version." );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/coldfusion-family.html" );
 script_set_attribute(attribute:"solution", value:
"Enter an IP (e.g. 127.0.0.1) in the Debug Settings within the 
ColdFusion Admin." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");


 script_set_attribute(attribute:"plugin_publication_date", value: "2001/11/07");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/07/01");
 script_cvs_date("$Date: 2017/04/27 19:46:26 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 summary["english"] = "Get ColdFusion Debug Information";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2001-2017 Felix Huber");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
 
port = get_http_port(default:80);


dir[0] = "/";
dir[1] = "/index.cfm";
dir[2] = "/index.cfml";
dir[3] = "/home.cfm";
dir[4] = "/home.cfml";
dir[5] = "/default.cfml";
dir[6] = "/default.cfm";


if(get_port_state(port))
{
 for (i = 0; dir[i] ; i = i + 1)
 {
        url = string(dir[i], "?Mode=debug");
        req = http_get(item:url, port:port);
        r = http_keepalive_send_recv(port:port, data:req);
	if( r == NULL ) exit(1, "The web server on port "+port+" failed to respond.");
       
	if("CF_TEMPLATE_PATH" >< r)
        	{
        		security_warning(port);
        		exit(0);
        	}
  }
  
 foreach dir (cgi_dirs())
 {
 dirz = string(dir, "/");
 url = string(dirz, "?Mode=debug");
 req = http_get(item:url, port:port);
 r =  http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )  exit(1, "The web server on port "+port+" failed to respond.");
 
 if("CF_TEMPLATE_PATH" >< r)
	    {
		    security_warning(port);
		    exit(0);
	    } 
 }
}
