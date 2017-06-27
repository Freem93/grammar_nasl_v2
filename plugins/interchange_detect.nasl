#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security 
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# Note: this service is *not* a web server, but it looks like it for 
# find_service
# HEAD / HTTP/1.0	(the only request it seems to recognize)
# HTTP/1.0 200 OK
# Last-modified: [15/August/2002:17:41:40 +0200]
# Content-type: application/octet-stream
#
# GET / HTTP/1.0   (or anything else, even not HTTP: GROUMPF\r\n)
# HTTP/1.0 404 Not found
# Content-type: application/octet-stream
#
# / not a Interchange catalog or help file.
#


include("compat.inc");

if(description)
{
 script_id(11128);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2002-0874");
 script_bugtraq_id(5453);
 script_osvdb_id(7133);
 script_xref(name:"DSA", value:"150");

 script_name(english:"Red Hat Interchange INET Mode Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running Red Hat Interchange." );
 script_set_attribute(attribute:"description", value:
"It seems that 'Red Hat Interchange' ecommerce and dynamic 
content management application is running in 'Inet' mode 
on this port.

Versions 4.8.5 and earlier are flawed and may disclose 
contents of sensitive files to attackers.

** Nessus neither checked Interchange version nor tried 
** to exploit the vulnerability" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3cc17f8" );
 script_set_attribute(attribute:"solution", value:
"Upgrade your software if necessary or configure it
for 'Unix mode' communication only." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/09/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/08/13");
 script_cvs_date("$Date: 2013/01/05 02:31:39 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Redhat Interchange e-commerce application detection");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2013 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 7786);
 exit(0);
}

####

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:7786);

w = http_send_recv_buf(port:port, data: 'NESSUS / HTTP/1.0\r\n\r\n',
  exit_on_fail: TRUE);
r = strcat(w[0], w[1], '\r\n', w[2]);
if ("/ not a Interchange catalog or help file" >< r) security_warning(port);

