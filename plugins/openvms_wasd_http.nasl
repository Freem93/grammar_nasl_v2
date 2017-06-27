#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(17150);
 script_version("$Revision: 1.11 $");
 script_cve_id("CVE-2002-1825");
 script_bugtraq_id(5811);
 script_osvdb_id(21288);
 
 script_name(english:"OpenVMS WASD HTTP Server Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that may allow arbitrary code
execution on the remote system." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host appears to be running WASD
HTTP server - a web server for the OpenVMS platform. 

The remote version of this software is affected by various
vulnerabilities that may allow an attacker to execute arbitrary code
on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenVMS WASD 7.2.4, 8.0.1 or 8.1" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/11/30");
 script_cvs_date("$Date: 2011/03/17 16:19:56 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Checks for the version of the remote HTTP Server");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("backport.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
if ( egrep(pattern:"^Server: HTTPd-WASD/([0-6]\.|7\.[01]\.|7\.2\.[0-3][^0-9]|8\.0\.0)", string:banner) )
	security_hole(port);
