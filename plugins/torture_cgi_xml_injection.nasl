#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(46196);
 script_version ("$Revision: 1.13 $");
 script_cvs_date("$Date: 2017/01/05 15:28:31 $");

 script_xref(name:"OWASP", value:"OWASP-DV-008");


 script_name(english: "CGI Generic XML Injection");
 script_summary(english: "Detect SOAP back-end and potential XML injection");

 script_set_attribute(attribute:"synopsis", value:
"A CGI application hosted on the remote web server is potentially
prone to an XML injection attack.");
 script_set_attribute(attribute:"description", value:
"By sending specially crafted parameters to one or more CGI scripts
hosted on the remote web server, Nessus was able to get a very
different response, which suggests that it may have been able to
modify the behavior of the application and directly access a SOAP
back-end. 

An attacker may be able to exploit this issue to bypass
authentication, read confidential data, modify the remote database, or
even take control of the remote operating system. 

Exploitation of XML injections is usually far from trivial. 

Note that this script is experimental and may be prone to false
positives especially, if a PHP application uses 'strip_tags()' to
sanitize user input." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4c60abd");
 script_set_attribute(attribute:"solution", value:
"Modify the affected CGI scripts so that they properly escape arguments, 
especially XML tags and special characters (angle brackets and slashes).");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cwe_id(
  91,  # XML Injection aka Blind XPath Injection
  713, # OWASP Top 10 2007 A2
  722, # OWASP Top 10 2004 A1
  727, # OWASP Top 10 2004 A6
  810, # OWASP Top Ten 2010 Category A1 - Injection
  928, # Weaknesses in OWASP Top Ten 2013
  929  # OWASP Top Ten 2013 Category A1 - Injection
 );
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/30");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl", "torture_cgi_load_estimation1.nasl");
 script_require_ports("Services/www", 80);
 script_timeout(43200);	# Timeout is managed by the script itself
 script_require_keys("Settings/enable_web_app_tests");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi_yesno.inc");
include("url_func.inc");

####

i = 0;
# There is a risk of FP with "<foo></ foo>" only: this may be deleted by
# the strip_tags() PHP function (protection against XSS)
poison_ok[i] = "<foo>bar</ foo>";	poison_ko[i++] = "</ foo>";

####

port = torture_cgi_init(vul:'ZI');


report = torture_cgis_yesno(port: port, vul: "ZI");
if (strlen(report) > 0)
{
  security_warning(port:port, extra: report);
}
