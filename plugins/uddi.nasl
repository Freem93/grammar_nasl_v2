#
# Copyright by John Lampe...j_lampe@bellsouth.net
#
# See the Nessus Scripts License for details
#
#


include("compat.inc");

if(description)
{
    script_id(11140);
    script_version ("$Revision: 1.22 $");

    script_name(english:"Web Server UDDI Detection");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server operates a business-oriented web services
registry." );
 script_set_attribute(attribute:"description", value:
"The remote web server supports Universal Description, Discovery, and
Integration (UDDI) requests, which are a standard way for businesses
to publish service listings." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/UDDI" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/10/09");
 script_cvs_date("$Date: 2011/03/11 21:52:40 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

    summary["english"] = "Find UDDI";
    script_summary(english:summary["english"]);
    script_category(ACT_GATHER_INFO);
    script_copyright(english:"This script is Copyright (C) 2002-2011 John Lampe...j_lampe@bellsouth.net");
    script_family(english:"Web Servers");
    script_dependencies("find_service1.nasl", "http_version.nasl");
    script_require_ports("Services/www", 80);
    exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("uddi.inc");
include("http_func.inc");

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);
if(get_kb_item("Services/www/" + port + "/embedded") ) exit(0);
mypath = "/";

mymessage = create_uddi_xml(ktype:"UDDI_QUERY_FBUSINESS", path:mypath, key:"", name:"e");  #loop through ETAOIN?
soc = open_sock_tcp(port);

if(soc) 
{
  send(socket:soc, data:mymessage);
  getreply = http_recv(socket:soc);
  close(soc);
}
else
{
  exit(0);
}



mystr = strstr(getreply, "serviceKey");
if (!mystr) 
{
   soaptest = strstr(getreply,"soap:Envelope");
   if (soaptest) {
      security_note(port);
      }
    exit(0);
}

flag = 0;
mykey = "";
for (i=12; flag < 1 ; i = i + 1) 
{                        #jump over servicekey=
    if ( (mystr[i] < "#") && (mystr[i] > "!") ) # BLECH!
        flag = flag + 1;
   else 
   	mykey = string(mykey, mystr[i]);
    
}

mymessage = create_uddi_xml(ktype:"UDDI_QUERY_GSERVICE_DETAIL", path:mypath, key:mykey);

soc = open_sock_tcp(port);
if (soc) 
{
   send(socket:soc, data:mymessage);
   getreply = http_recv(socket:soc);
}

if (egrep(pattern:mykey, string:getreply)) 
{
	security_note(port);
        exit(0);
}

if (report_paranoia > 1 && egrep(pattern: ".*200 OK.*", string:getreply)) 
{
        mywarning = string(
          "\n",
          "The server responded with a 200 response code, which could indicate it\n",
          "supports UDDI queries, although Nessus didn't find anything in the\n",
          "response to confidently identify it as such."
        );
	security_note(port:port, extra:mywarning);
	exit(0);
}
