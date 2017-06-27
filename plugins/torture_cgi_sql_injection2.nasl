#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(42479);
 script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2016/11/23 20:42:25 $");

 script_name(english:"CGI Generic SQL Injection (2nd pass)");
 script_summary(english:"Find SQL injections triggered by other attacks.");


 script_set_attribute(attribute:"synopsis", value:"A web application is potentially vulnerable to SQL injection.");
 script_set_attribute(attribute:"description", value:
"By providing specially crafted parameters to CGIs, Nessus was able to
get an error from the underlying database. This error suggests that
the CGI is affected by a SQL injection vulnerability.

An attacker may exploit this flaw to bypass authentication, read
confidential data, modify the remote database, or even take control of
the remote operating system.");
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/SQL_injection");
 script_set_attribute(attribute:"see_also", value:"http://www.securiteam.com/securityreviews/5DP0N1P76E.html");
 # http://web.archive.org/web/20100327210333/http://www.securitydocs.com/library/2651
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5c79f44");
 # http://projects.webappsec.org/w/page/13246963/SQL%20Injection
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11ab1866");
 script_set_attribute(attribute:"solution", value:"Modify the relevant CGIs so that they properly escape arguments.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cwe_id(
  20,  # Improper input validation
  77,  # Improper neutralization of special characters
  89,  # SQL injection
  713, # OWASP Top 10 2007 A2
  722, # OWASP Top 10 2004 A1
  727, # OWASP Top 10 2004 A6
  751, # 2009 Top 25 - Insecure Interaction Between Components
  801, # 2010 Top 25 - Insecure Interaction Between Components
  810, # OWASP Top Ten 2010 Category A1 - Injection
  928, # Weaknesses in OWASP Top Ten 2013
  929  # OWASP Top Ten 2013 Category A1 - Injection
 );

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/12");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_END);
 script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl");
 script_require_ports("Services/www");
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
resp_l = get_kb_list("www/"+port+"/cgi_*/response/*");

prev_code = '';
foreach k (sort(keys(resp_l)))
{
  v = eregmatch(string: k, pattern: "/cgi_([A-Z][A-Z])/response/([0-9]+)");
  if (isnull(v)) continue;
  code = v[1]; nb = v[2];
  # Already known as a non blind SQL injection?
  if (code =~ "^S[ICHN]$") continue;

  rep1 = "";
  r = get_kb_blob("www/"+port+"/cgi_"+code+"/response/"+nb);
  if (isnull(r))
    r = decode_kb_blob(value: resp_l[k]);

  # Ignore Tomcat JNDI Datasource HOW-TO page to prevent FP
  if (ereg(pattern:'JNDI Datasource HOW-TO', string:r, icase:TRUE, multiline:TRUE)) continue;

  txt = extract_pattern_from_resp(string: r, pattern: "GL");
  if (strlen(txt) > 0)
  {
    req = get_kb_blob("www/"+port+"/cgi_"+code+"/request/"+nb);
    if (! req) continue;
    rep1 = strcat(rep1, '-------- request  --------\n',
   chomp(req),
   '\n------------------------\n\n-------- output --------\n',
   txt, '------------------------\n\n');
  }

  if (strlen(rep1) > 0)
  {
    if (code != prev_code)
    {
      report = strcat(report,
'\nDuring testing for ', torture_cgi_name(code: code), ' vulnerabilities, ',
'\n SQL errors were noticed, suggesting that the scripts / parameters ',
'\nlisted below may also be vulnerable to SQL Injection (SQLi).\n\n');
      prev_code = code;
    }
    report += rep1;
  }
}

if (strlen(report) > 0)
{
  security_hole(port:port, extra: report);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}
