#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(51973);
 script_version ("$Revision: 1.10 $");
 script_name(english: "CGI Generic SQL Injection (Parameters Names)");


 script_set_attribute(attribute:"synopsis", value:
"A web application is potentially vulnerable to SQL injection
attacks." );
 script_set_attribute(attribute:"description", value:
"By providing specially crafted parameters to CGIs, Nessus was able to
get an error from the underlying database.  This error suggests that
the CGI is affected by a SQL injection vulnerability. 

An attacker may be able to exploit this flaw to bypass authentication,
read confidential data, modify the remote database, or even take
control of the remote operating system." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/SQL_injection" );
 script_set_attribute(attribute:"see_also", value:"http://www.securiteam.com/securityreviews/5DP0N1P76E.html" );
 # https://web.archive.org/web/20101230192555/http://www.securitydocs.com/library/2651
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed792cf5" );
 script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/SQL-Injection");
 script_set_attribute(attribute:"solution", value:
"Modify the relevant CGIs so that they properly escape arguments." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cwe_id(
  20,  # Improper input validation
  77,  # Improper neutralization of special characters
  89,  # SQL injection
  203, # Information Exposure Through Discrepancy
  209, # Information Exposure Through an Error Message
  713, # OWASP Top 10 2007 A2
  717, # OWASP Top Ten 2007 Category A6 - Information Leakage and Improper Error Handling
  722, # OWASP Top 10 2004 A1
  727, # OWASP Top 10 2004 A6
  751, # 2009 Top 25 - Insecure Interaction Between Components
  801, # 2010 Top 25 - Insecure Interaction Between Components
  810, # OWASP Top Ten 2010 Category A1 - Injection
  928, # Weaknesses in OWASP Top Ten 2013
  929, # OWASP Top Ten 2013 Category A1 - Injection
  933  # OWASP Top Ten 2013 Category A5 - Security Misconfiguration
 );
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/14");
 script_cvs_date("$Date: 2017/01/05 15:28:31 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english: "Common SQL injection techniques on parameters names");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl", "torture_cgi_load_estimation1.nasl");
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
include("torture_cgi_param_names.inc");
include("url_func.inc");


####

global_patterns = sql_error_patterns;

single_quote = raw_string(0x27);
double_quote = raw_string(0x22);

i = 0;
poison[i++] = single_quote;
poison[i++] = single_quote + "%22";
poison[i++] = "9%2c+9%2c+9";
poison[i++] = "bad_bad_value" + single_quote;
poison[i++] = "%3B";
poison[i++] = single_quote + " or 1=1-- ";
poison[i++] = " or 1=1-- ";
poison[i++] = "char(39)";
poison[i++] = "%27";
poison[i++] = "--+";
poison[i++] = "#";
poison[i++] = "/*";
poison[i++] = double_quote;
poison[i++] = "%22";
poison[i++] = "%2527";
poison[i++] = single_quote + "+convert(int,convert(varchar,0x7b5d))+" + single_quote;
poison[i++] = "convert(int,convert(varchar,0x7b5d))";
poison[i++] = single_quote + "+convert(varchar,0x7b5d)+" + single_quote;
poison[i++] = "convert(varchar,0x7b5d)";
poison[i++] = single_quote + "%2Bconvert(int,convert(varchar%2C0x7b5d))%2B" + single_quote;
poison[i++] = single_quote + "%2Bconvert(varchar%2C0x7b5d)%2B" + single_quote;
poison[i++] = "convert(int,convert(varchar%2C0x7b5d))";
poison[i++] = "convert(varchar%2C0x7b5d)";
# from torturecgis.nasl
poison[i++] = "whatever)";
# The next two patterns work if the application doubles single quotes 
# and truncate the output. 
if (experimental_scripts || thorough_tests)
{
poison[i++] = "''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''";
poison[i++] = "a''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''";
# May be useful for XPath injections too
poison[i++] = single_quote + "--";
}

flaws_and_patterns = make_array();
for (i = 0; ! isnull(poison[i]); i ++)
 flaws_and_patterns[poison[i]] = "GL";
poison = NULL;	# Free memory

####

port = torture_cgi_init(vul:'SN');


if (thorough_tests)
 e = make_list("pl", "php", "php3", "php4", "php5", "cgi", "asp", "aspx");
else
 e = NULL;

report = run_injection_param_names(vul: "SN");

if (strlen(report) > 0)
  security_hole(port:port, extra: report);

