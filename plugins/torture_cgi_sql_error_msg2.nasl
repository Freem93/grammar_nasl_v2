#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(48927);
 script_version ("$Revision: 1.10 $");
 script_cvs_date("$Date: 2016/10/21 19:57:32 $");

 script_name(english: "CGI Generic SQL Injection Detection (potential, 2nd order, 2nd pass)");

 script_set_attribute(attribute:"synopsis", value:
"A web application displays error messages." );
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
database, or even take control of the remote operating system." );
 # http://www.catonmat.net/blog/wp-content/uploads/2008/07/second-order-sql-injection-attacks.pdf
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dee0c8cb");
 # http://www.cisco.com/web/about/security/intelligence/sql_injection.html#5
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c91db6e");
 # http://web.archive.org/web/20100717120125/http://st-curriculum.oracle.com/tutorial/SQLInjection/html/lesson1/les01_tm_attacks2.htm
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c5cd2c92");
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/SQL_injection" );
 script_set_attribute(attribute:"see_also", value:"http://www.securiteam.com/securityreviews/5DP0N1P76E.html" );
 # https://web.archive.org/web/20101230192555/http://www.securitydocs.com/library/2651
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed792cf5" );
 script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/SQL-Injection");
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

 script_summary(english: "Look for SQL error messages.");

 script_category(ACT_END);

 script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/enable_web_app_tests");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi.inc");

####

global_patterns = sql_error_patterns;

port = get_kb_item("Services/www");
if (! port) exit(0);

report = "";
resp_l = get_kb_list_or_exit("wwwFP/"+port+"/cgi_S*/response/*");

foreach k (keys(resp_l))
{
  v = eregmatch(string: k, pattern: "/cgi_(S[A-Z])/response/([0-9]+)");
  if (isnull(v)) continue;
  code = v[1]; nb = v[2];

  r = get_kb_blob("wwwFP/"+port+"/cgi_"+code+"/response/"+nb);
  if (isnull(r))
    r = decode_kb_blob(value: resp_l[k]);
  txt = extract_pattern_from_resp(string: r, pattern: "GL");
  if (strlen(txt))
  {
    req = get_kb_blob("wwwFP/"+port+"/cgi_"+code+"/request/"+nb);
    if (! req) continue;
    report = strcat(report, '-------- request --------\n', 
   chomp(req), 
   '\n------------------------\n\n-------- output --------\n', 
   txt, '------------------------\n\n');
  }
}

if (strlen(report) > 0)
{
  security_hole(port:port, extra: report);
  if (report_paranoia > 1)
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  exit(0);
}

