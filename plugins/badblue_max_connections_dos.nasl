#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(14350);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2004-1727");
 script_bugtraq_id(10983);
 script_osvdb_id(9107);

 script_name(english:"BadBlue Connection Saturation Remote DoS"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote BadBlue web server has a bug which 
may allow attackers to prevent it from serving pages properly. It is 
possible to disable the remote BadBlue server by issuing approximately
24 concurrent connections to the remote host. An attacker may exploit 
this flaw by issuing over 24 connections to the remote server and 
waiting indefinitely, thus preventing legitimate users from being able 
to connect to this service at all." );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/20");
 script_cvs_date("$Date: 2011/03/17 16:19:55 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();
 
 script_summary(english:"Get the version of the remote badblue server");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_require_ports("Services/www", 80);
 script_dependencies("find_service1.nasl", "http_version.nasl");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if(!banner)exit(0);

vulnerable = egrep(pattern:"^Server: BadBlue/(1\.|2\.[0-5])", string:banner);
if(vulnerable)security_warning(port);


