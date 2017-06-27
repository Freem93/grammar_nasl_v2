#
# written by Gareth Phillips - SensePost (www.sensepost.com)
# Released under GPLv2

# Changes by Tenable:
# - Longer regex to match on
# - Also match on the server version number
# - Revised plugin title, changed family (4/3/2009)
# - Updated to use compat.inc, Added CVSS score (11/20/2009)


include("compat.inc");

if(description)
{
 script_id(18650);
 script_version ("$Revision: 1.9 $");
 script_bugtraq_id (7975);
 script_osvdb_id(2204);

 script_name(english:"Sambar Server search.pl results.stm Overflow DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Sambar Server, a web server package.

The remote version of this software contains a flaw that may 
allow an attacker to crash the service remotely.

A buffer overflow was found in the /search/results.stm application
that comes shipped with Sambar Server. 

Vulnerable versions: Sambar Server 4.x
		     Sambar Server 5.x
		     Sambar Server 6.0" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to current release of this software" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/06/21");
 script_cvs_date("$Date: 2011/03/17 01:57:39 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 script_summary(english:"Sambar Search Results Buffer Overflow DoS");

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2011 SensePost");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# Code Starts Here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port || ! get_port_state(port) ) exit(0);

req = http_get(item:"/search/results.stm", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if( res == NULL ) exit(0);

if ( egrep(pattern:"^Server: Sambar (4\.|5\.[01]([^0-9]|$))", string:res, icase:TRUE) )
  security_hole (port);
else if ( egrep(pattern:"&copy; 1997-(199[8-9]|200[0-3]) Sambar Technologies, Inc. All rights reserved.", string:res) ) 
  security_hole (port);

