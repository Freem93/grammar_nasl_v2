#
# This script was written by Vincent Renardias <vincent@strongholdnet.com>
#
# Licence : GPL v2
#

# Changes by Tenable:
# - Standardized title (4/2/2009)


include("compat.inc");

if(description)
{
 script_id(10678);
 script_version ("$Revision: 1.26 $");
 script_osvdb_id(562);
 script_cvs_date("$Date: 2017/04/27 14:49:39 $");

 script_name(english:"Apache mod_info /server-info Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server discloses information about its configuration." );
 script_set_attribute(attribute:"description", value:
"It is possible to obtain an overview of the remote Apache web server's
configuration by requesting the URL '/server-info'.  This overview
includes information such as installed modules, their configuration,
and assorted run-time settings." );
 script_set_attribute(attribute:"see_also", value:"http://httpd.apache.org/docs/current/mod/mod_info.html" );
 script_set_attribute(attribute:"solution", value:
"If required, update Apache's configuration file(s) to either disable
mod_info or ensure that access is limited to valid users / hosts." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/05/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/01/01");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:apache:http_server");
script_end_attributes();

 
 summary["english"] = "Requests /server-info";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001-2017 StrongHoldNet");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
str = "Apache Server Information";

if(get_port_state(port) )
{
  buffer = http_get(item:"/server-info", port:port);
  data = http_keepalive_send_recv(port:port, data:buffer);
  if( str >< data )
  {
   security_warning(port);
  }
}
