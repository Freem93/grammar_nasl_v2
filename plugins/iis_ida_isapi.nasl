#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# www.westpoint.ltd.uk
#
#
# Modified by rd to have a language independent pattern matching, thanks
# to the remarks from Nicolas Gregoire <ngregoire@exaprobe.com>
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(10695);
 script_version ("$Revision: 1.36 $");
 script_cvs_date("$Date: 2014/04/25 22:31:27 $");

 script_name(english:"Microsoft IIS .IDA ISAPI Filter Enabled");
 
 script_set_attribute(attribute:"synopsis", value:
"Indexing Service filter is enabled on the remote Web server." );
 script_set_attribute(attribute:"description", value:
"The IIS server appears to have the .IDA ISAPI filter mapped.

At least one remote vulnerability has been discovered for the .IDA
(indexing service) filter. This is detailed in Microsoft Advisory
MS01-033, and gives remote SYSTEM level access to the web server. 

It is recommended that even if you have patched this vulnerability that
you unmap the .IDA extension, and any other unused ISAPI extensions
if they are not required for the operation of your site." );
 script_set_attribute(attribute:"solution", value:
"To unmap the .IDA extension:
 1.Open Internet Services Manager. 
 2.Right-click the Web server choose Properties from the context menu. 
 3.Master Properties 
 4.Select WWW Service -> Edit -> HomeDirectory -> Configuration 
 5.Remove the reference to .ida from the list.

In addition, you may wish to download and install URLSCAN from the
Microsoft Technet website.  URLSCAN, by default, blocks all .ida
requests to the IIS server." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/06/19");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
script_end_attributes();

 
 summary["english"] = "Tests for IIS .ida ISAPI filter";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001-2014 Matt Moore");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check makes a request for NULL.ida
include("http_func.inc");
include("global_settings.inc");

port = get_http_port(default:80);

if ( get_kb_item("Services/www/" + port + "/embedded") ) exit(0);
sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);
if(get_port_state(port))
{ 
 req = http_get(item:"/NULL.ida", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 look = strstr(r, "<HTML>");
 look = look - string("\r\n");
 if(egrep(pattern:"^.*HTML.*IDQ.*NULL\.ida.*$", string:look)) security_note(port);
 }
}
