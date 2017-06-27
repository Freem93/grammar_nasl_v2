#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10535);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2000-0967");
 script_bugtraq_id(1786);
 script_osvdb_id(434);

 script_name(english:"PHP Error Log Format String Command Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code might be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The  version of PHP that is running on the remote host is older than 
3.0.17 or 4.0.3.

If the option 'log_errors' is set to 'On' in php.ini, then an attacker 
may execute arbitrary code on this host." );
 script_set_attribute(attribute:"solution", value:
"Make sure that 'log_errors' is set to 'Off' in your php.ini, or install 
the latest version of PHP." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/10/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/10/14");
 script_cvs_date("$Date: 2012/09/10 21:39:38 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:php:php");
script_end_attributes();

 script_summary(english:"Checks for version of PHP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2012 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

 banner = get_http_banner(port:port);
 if(!banner)exit(0);

 serv = egrep(string:banner, pattern:"^Server:.*$");
 if(ereg(pattern:"(.*PHP/3\.0\.((1[0-6])|([0-9]([^0-9]|$))))|(.*PHP/4\.0\.[0-2]([^0-9]|$))",
          string:serv))
 {
   security_warning(port);
 }
 
