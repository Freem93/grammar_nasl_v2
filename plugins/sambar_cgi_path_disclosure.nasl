#
# (C) Tenable Network Security, Inc.
#

# References:
# From: <gregory.lebras@security-corporation.com>
# To: vulnwatch@vulnwatch.org
# Date: Thu, 27 Mar 2003 15:25:40 +0100
# Subject: [SCSA-012] Multiple vulnerabilities in Sambar Server
#
# Vulnerables:
# Sambar WebServer v5.3 and below 
#

include("compat.inc");

if (description)
{
 script_id(11775);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2016/11/02 14:37:09 $");

 script_cve_id("CVE-2003-1284");
 script_bugtraq_id(7207, 7208);
 script_osvdb_id(5093, 5094);

 script_name(english:"Sambar Server Multiple CGI Environment Variable Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains CGI scripts that are affected by information
disclosure vulnerabilities.");
 script_set_attribute(attribute:"description",  value:
"The remote web server appears to be Sambar Server and makes available
the 'environ.pl' and/or 'testcgi.exe' CGI scripts.  These are included
by default and reveal the server's installation directory along with
other information that could prove useful to an attacker.

Note that this version is also likely to be affected by other issues,
including arbitrary code execution, although this plugin has not
checked for them.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84fefeb2");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Mar/416");
 script_set_attribute(attribute:"solution", value:"Delete the affected CGI scripts.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/25");
 script_set_attribute(attribute:"vuln_publication_date", value:"2003/03/27");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Some CGIs reveal the web server installation directory");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/sambar");
 exit(0);
}

# The script code starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if (!banner) exit(1, "No HTTP banner on port "+port);
if (!egrep(pattern:"^Server:.*SAMBAR.*", string:banner)) exit(0, "The web server on port "+port+" is not Sambar");

w = http_send_recv3(method:"GET", item:"/cgi-bin/testcgi.exe", port:port);
if (isnull(w)) exit(1, "The web server on port "+port+ " did not answer");
res = strcat(w[0], w[1], '\r\n', w[2]);

if("SCRIPT_FILENAME" >< res ) {
        security_warning(port);
        exit(0);
        }
        
        
w = http_send_recv3(method:"GET", item:"/cgi-bin/environ.pl", port:port);  
if (isnull(w)) exit(1, "The web server on port "+port+ " did not answer");
res = strcat(w[0], w[1], '\r\n', w[2]);

if("DOCUMENT_ROOT" >< res) security_warning(port);
