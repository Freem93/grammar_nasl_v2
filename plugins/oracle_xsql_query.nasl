#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
# www.westpoint.ltd.uk
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to www.kb.cert.org
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, added CVE/BID/OSVDB, description touch-up (6/12/09)


include("compat.inc");

if(description)
{
 script_id(10613);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2002-1631");
 script_bugtraq_id(6556);
 script_osvdb_id(509);
 script_xref(name:"CERT", value:"717827");

 script_name(english:"Oracle XSQL query.xsql sql Parameter SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is vulnerable to information disclosure." );
 script_set_attribute(attribute:"description", value:
"One of the sample applications that comes with the Oracle XSQL Servlet
 allows an attacker to make arbitrary queries to the Oracle database
(under an unprivileged account). 
Whilst not allowing an attacker to delete or modify database contents, 
this flaw can be used to enumerate database users and view table names." );
 script_set_attribute(attribute:"solution", value:
"Sample applications should always be removed from production servers." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/02/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/02/06");
 script_set_attribute(attribute:"patch_publication_date", value: "2002/02/06");
 script_cvs_date("$Date: 2014/07/11 19:10:05 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:application_server");
 script_end_attributes();

 
 script_summary(english:"Tests for Oracle XSQL Sample Application Vulnerability");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2014 Matt Moore");
 script_family(english:"Databases");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Checqueryk starts here
# Check uses a default sample page supplied with the XSQL servlet. 

include("http_func.inc");
include("global_settings.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if (! banner || ! egrep(pattern:"^Server:.*Oracle", string:banner, icase:TRUE) ) exit(0);

if(get_port_state(port))
{ 
 req = http_get(item:"/xsql/demo/adhocsql/query.xsql", port:port);
 r   = http_keepalive_send_recv(port:port, data:req);
 if("USERNAME" >< r) exit(0);

 req = http_get(item:"/xsql/demo/adhocsql/query.xsql?sql=select%20username%20from%20ALL_USERS", port:port);
 r   = http_keepalive_send_recv(port:port, data:req);
 if("USERNAME" >< r)	
 	security_warning(port);
}
