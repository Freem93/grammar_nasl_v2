#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(48926);
 script_version ("$Revision: 1.15 $");
 script_cvs_date("$Date: 2017/01/05 15:28:31 $");

 script_name(english: "CGI Generic 2nd Order SQL Injection Detection (potential)");

 script_set_attribute(attribute:"synopsis", value:
"A web application displays SQL error messages." );
 script_set_attribute(attribute:"description", value:
"By calling discovered CGIs with previously gathered values, SQL error
messages were induced. 

* This could be a result of transient SQL failure :

However, even if the application is not vulnerable to an injection,
SQL error messages often reveal the structure of the database and
query information.  Such information could help an attacker.  Further,
this may indicate the application is not resilient to increased
traffic or unexpected data and could lead to a denial of service
problem. 

* They might be triggered by a 'second order' SQL injection :

Second Order SQL injection is a term used to describe an injection in
which a crafted SQL query is injected into the application, but not
immediately acted upon.  The injected content may be stored and
executed at a later time.  An attacker may exploit SQL injections to
bypass authentication, read confidential data, modify the remote
database, or even take control of the remote operating system.");
 # http://www.cisco.com/web/about/security/intelligence/sql_injection.html#5
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c91db6e");
 # http://web.archive.org/web/20100717120125/http://st-curriculum.oracle.com/tutorial/SQLInjection/html/lesson1/les01_tm_attacks2.htm
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c5cd2c92");
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/SQL_injection" );
 script_set_attribute(attribute:"see_also", value:"http://www.securiteam.com/securityreviews/5DP0N1P76E.html" );
  # http://web.archive.org/web/20090126063542/http://www.securitydocs.com/library/2651
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?05c2d95d" );
  # http://projects.webappsec.org/w/page/13246963/SQL%20Injection
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11ab1866");
 script_set_attribute(attribute:"see_also", value:"https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet");
 script_set_attribute(attribute:"see_also", value:"http://www.technicalinfo.net/papers/SecondOrderCodeInjection.html");
  # http://www.codeproject.com/Articles/9378/SQL-Injection-Attacks-and-Some-Tips-on-How-to-Prev
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c750d0e6");

 script_set_attribute(attribute:"solution", value:
"- Modify the relevant CGIs so that they properly escape arguments. 

- Filter error messages out." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/30");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english: "Look for SQL error messages");

 # Try to run later
 script_category(ACT_MIXED_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/enable_web_app_tests");
 script_timeout(43200);	# Timeout is managed by the script itself
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi.inc");

function torture_cgi_response_post_check(resp) { return 0; }	# stub

####

# See torture_cgi_sql_injection_headers.nasl
if ((get_kb_item("Settings/PCI_DSS") || report_paranoia < 2) && get_kb_item('/tmp/launched/SH/'+port))
{
  if (test_arg_val == 'single')
    exit(0, "Second order SQL injections have already been tested.");
  if (! thorough_tests)
    exit(0, "Second order SQL injections have already been partially tested.");
}

flaws_and_patterns = make_array(
  "VALUE",	# Blank bullet
  "GL" );	# Global SQL patterns

global_patterns = sql_error_patterns;

####

port = torture_cgi_init(vul:'S2');


if (thorough_tests || experimental_scripts)
 e = make_list("pl", "php", "php3", "php4", "php5", "cgi", "asp", "aspx");
else
 e = NULL;

report = torture_cgis(port: port, vul: "S2", ext_l: e);

if (strlen(report) > 0)
{
  security_hole(port:port, extra: report);
}
