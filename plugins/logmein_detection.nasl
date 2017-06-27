#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(34266);
 script_version ("$Revision: 1.8 $");
 script_cvs_date("$Date: 2011/09/13 13:34:36 $");
 
 script_name(english: "LogMeIn Agent Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"A LogMeIn agent is running on this port." );
 script_set_attribute(attribute:"description", value:
"LogMeIn is a remote control application. 

In the typical mode of operation, a user does not connect to the
LogMeIn agent on the host directly.  Rather, all traffic, including
credentials, is routed through the vendor's servers, with traffic
possibly tunneled through firewalls. 

Alternatively, it is possible to access the LogMeIn agent directly by
providing Windows credentials." );
 script_set_attribute(attribute:"see_also", value:"http://www.logmein.com/" );
 script_set_attribute(attribute:"solution", value:
"Make sure that use of this software is in agreement with your
organization's security policies and that users understand both how to
use it appropriately and the risks of routing session traffic through
third-party hosts." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/09/23");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english: 'Identifies LogMeIn HTTP server');
 
 script_category(ACT_GATHER_INFO); 
 script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");
 script_family(english: "Windows");
 script_dependencie("http_version.nasl");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

ports_l = make_service_list("Services/www", 2002);

# Note: LogMeIn works on SSL/TLS. But if you send a GET request on plain TCP,
# it will reply this kind of thing:
# HTTP/1.1 302 Moved Temporarily
# Content-Type: application/octet-stream
# Set-Cookie: RASID=ynAMVbXDFUmZDkFSAD59axmY7N82jPa; path=/
# Connection: close
# Accept-Ranges: none
# Location: https://HOST:2002/
# Date: Fri, 19 Sep 2008 19:49:28 GMT
# Content-Length: 0
# Server: LogMeIn/4.0.762
# Set-Cookie: UAID=ku8qyk0jCZdUd5bPlFR1n04NSsbs35Q; path=/; expires=Thu, 18 Dec 2008 19:49:28 GMT
# The server field is present in any case, so this will work wether the SSL
# tests are properly configured or not

foreach port (ports_l)
 if (get_port_state(port))
 {
   banner = get_http_banner(port: port);
   if (! banner) continue;

   v = eregmatch( string: banner, 
       		  pattern: '\r\nServer:[ \t]*LogMeIn/([0-9.]+)[ \t]*\r\n');
   if (! isnull(v))
   {
     set_kb_item(name:"Services/www/logmein", value:port);
     security_note(port:port, extra: '\nLogMeIn/'+v[1]+' is running.\n');
   }
 }
