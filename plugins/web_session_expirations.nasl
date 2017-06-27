#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(47863);
 script_version ("$Revision: 1.2 $");
 script_cvs_date("$Date: 2011/03/19 11:27:54 $");

 script_name(english: "Web Tests Session Expiration Errors");

 script_set_attribute(attribute:"synopsis", value:
"Nessus was logged out while running the web attacks." );
 script_set_attribute(attribute:"description", value:
"Nessus encountered trouble while running the web tests against the
remote web server - test results may be incomplete." );

 script_set_attribute(attribute:"solution", value:
"Rescan with less parallelism or by requesting more session refresh,
for example, by changing the following options in the scan policy :

  - Preferences -> HTTP login page -> re-authenticate delay (seconds)

  - Options -> Number of hosts in parallel (max_hosts)

  - Options -> Number of checks in parallel (max_checks)" );

 script_set_attribute(attribute:"risk_factor", value: "None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/27");
 script_set_attribute(attribute:"plugin_type", value:"summary");
 script_end_attributes();

 script_summary(english: "Reports web session expiration errors");
 script_category(ACT_END);

 script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
# script_dependencie("web_app_test_settings.nasl", "global_settings.nasl");
 script_require_ports("Services/www");
 script_require_keys("Settings/enable_web_app_tests");
 exit(0);
}

include("global_settings.inc");

####

port = get_kb_item("Services/www");
if (!port) exit(0, "No web services were detected.");

rep = "";

l = get_kb_list("www/"+port+"/*.nasl/auth_*");
if (isnull(l)) exit(0, "No session expiration on port "+port+".");
l = sort(keys(l));

ko = make_array(); ok = make_array(); scripts = make_array();
prev = NULL;
foreach k (l)
{
  if (k == prev) continue;
  prev = k;
  v = eregmatch(string: k, pattern: "/([^/]+)/auth_([OK][KO])$");
  if (isnull(v)) continue;
  name = v[1]; type = v[2];
  n = get_kb_item(k); n = int(n);
  if (n > 0)
  {
    if (type == "OK")
      ok[name] = n;
    else
      ko[name] = n;
    scripts[name] = TRUE;
  }
}

ok_txt = "";
ko_txt = "";

foreach k (keys(scripts))
{
  n = ok[k] + ko[k];
  if (ko[k] == 0)
    ok_txt = strcat(ok_txt, 
" - during the execution of ", k, ', the \n',
' session expired ', ok[k], ' time(s) but re-authentication always succeeded.\n');
  else
    ko_txt = strcat(ko_txt, 
' - during the execution of ', k, ', the \n',
' session expired ', n, ' time(s) and re-authentication failed ', ko[k], ' time(s).\n');
}

rep = "";
if (ko_txt) rep = ko_txt;
if (ok_txt) rep = strcat(rep, ok_txt);

if (rep)
{
 security_note(port: port, extra: '\n'+rep);
 if (COMMAND_LINE) display(rep);
}

