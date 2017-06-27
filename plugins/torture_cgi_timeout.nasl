#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(39470);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/09/21 18:00:45 $");

  script_name(english:"CGI Generic Tests Timeout");
  script_summary(english:"Generic CGI tests timed out");

  script_set_attribute(attribute:"synopsis", value:
"Some generic CGI attacks ran out of time.");
  script_set_attribute(attribute:"description", value:
"Some generic CGI tests ran out of time during the scan. The results
may be incomplete.");
  script_set_attribute(attribute:"solution", value:
"Consider increasing the 'maximum run time (minutes)' preference for
the 'Web Applications Settings' in order to prevent the CGI scanning
from timing out. Less ambitious options could also be used, such as :

  - Test more that one parameter at a time per form :
    'Test all combinations of parameters' is much slower
    than 'Test random pairs of parameters' or 'Test all
    pairs of parameters (slow)'.

  - 'Stop after one flaw is found per web server (fastest)'
    under 'Do not stop after the first flaw is found per web
    page' is quicker than 'Look for all flaws (slowest)'.

  - In the Settings/Advanced menu, try reducing the value
    for 'Max number of concurrent TCP sessions per host' or
    'Max simultaneous checks per host'.");
  script_set_attribute(attribute:"risk_factor", value: "None" );
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/19");

  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_end_attributes();

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_category(ACT_END);
  script_family(english: "CGI abuses");

  script_dependencie("web_app_test_settings.nasl", "global_settings.nasl");
  script_require_ports("Services/www");
  script_require_keys("Settings/enable_web_app_tests");

  exit(0);
}

include("global_settings.inc");
include("torture_cgi_names.inc");

####

t = int(get_kb_item("Settings/HTTP/max_run_time"));
if (t <= 0) exit(0);

port = get_kb_item("Services/www");
if (! port) exit(0);

r1 = ''; r2 = '';
l = get_kb_list("torture_CGI/timeout/"+port);
if (! isnull(l))
  foreach k (make_list(l)) r1 = strcat(r1, '- ', torture_cgi_name(code: k), '\n');

l = get_kb_list("torture_CGI/unfinished/"+port);
if (! isnull(l))
  foreach k (make_list(l))
    r2 = strcat(r2, '- ', torture_cgi_name(code: k), '\n');

r = '';
if (r1) r = strcat('The following tests timed out without finding any flaw :\n', r1, '\n');
if (r2) r = strcat(r, 'The following tests were interrupted and did not report all possible flaws :\n', r2, '\n');

if (r) security_note(port: port, extra: r);
