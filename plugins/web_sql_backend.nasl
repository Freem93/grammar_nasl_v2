#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(44670);
 script_version("$Revision: 1.10 $");
 script_cvs_date("$Date: 2013/09/26 15:03:37 $");

 script_name(english: "Web Application SQL Backend Identification");
 script_summary(english: "Identifies SQL backend by looking at error messages");

 script_set_attribute(attribute:"synopsis", value:
"A web application's SQL backend can be identified.");
 script_set_attribute(attribute:"description", value:
"At least one web application hosted on the remote web server is built
on a SQL backend that Nessus was able to identify by looking at
error messages. 

Leaking this kind of information may help an attacker fine-tune
attacks against the application and its backend.");
 script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/Fingerprinting");
 script_set_attribute(attribute:"solution", value:"Filter out error messages.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/19");

 script_set_attribute(attribute:"plugin_type", value:"remote"); 
 script_end_attributes();

 script_category(ACT_END);
 script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
include("torture_cgi_sql_inj_msg.inc");


####

port = torture_cgi_init();

db = extract_sql_backend_from_kb(port: port);

kl = keys(db);
report = "";
n = max_index(kl);
if (n == 0) exit(0, "No DB backend has been identified on port "+port+".");

report = "";
foreach k (kl) report = strcat(report, k, '\n');

if (report_verbosity > 0)
{
  l = list_uniq(make_list(db));
  url_l = "";
  n = 0;
  foreach k (l)
  {
    url_l = strcat(url_l, build_url(port:port, qs: k), '\n');
    if (n ++ >= 100)
    {
      url_l = strcat(url_l, '[...]\n');
      break;
    }
  }
}

if (max_index(kl) == 1)
{
  e = '\nThe web application appears to be based on '+report;
  if (report_verbosity > 0)
    e = strcat(e, '\nThis information was leaked by these URLs :\n', url_l);
  security_warning(port: port, extra: e);
  set_kb_item(name: 'www/'+port+'/SQL_back_end', value: chomp(report));
}
else
{
  e = '\nThe web application might be based on one of these SQL engines :\n' + report;
  if (report_verbosity > 0)
    e = strcat(e, '\nThis information was leaked by these URLs :\n', url_l);
  security_warning(port: port, extra: e);
  set_kb_item(name: 'www/'+port+'/SQL_back_end', value: chomp(report));
}
# else exit(0, "Nessus hesitates between "+n+" SQL engines on port "+port);
