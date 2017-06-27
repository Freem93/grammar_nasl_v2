#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(40406);
 script_version ("$Revision: 1.9 $");

 script_name(english: "CGI Generic Tests HTTP Errors");

 script_set_attribute(attribute:"synopsis", value:
"Nessus encountered errors while running its generic CGI attacks." );
 script_set_attribute(attribute:"description", value:
"Nessus ran into trouble while running its generic CGI tests against
the remote web server (for example, connection refused, timeout, etc). 
When this happens, Nessus aborts the current test and switches to the
next CGI script on the same port or to another web server.  Thus, test
results may be incomplete." );

 script_set_attribute(attribute:"solution", value:
"Rescan with a longer network timeout or less parallelism for example,
by changing the following options in the scan policy :

  - Network -> Network Receive Timeout (check_read_timeout)

  - Options -> Number of hosts in parallel (max_hosts)

  - Options -> Number of checks in parallel (max_checks)" );

 script_set_attribute(attribute:"risk_factor", value: "None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/28");
 script_cvs_date("$Date: 2011/09/21 18:57:16 $");
 script_set_attribute(attribute:"plugin_type", value: "summary");
 script_end_attributes();

 script_summary(english: "Reports generic CGI test errors");
 script_category(ACT_END);

 script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
# script_dependencie("web_app_test_settings.nasl", "global_settings.nasl");
 script_require_ports("Services/www");
 script_require_keys("Settings/enable_web_app_tests");
 exit(0);
}

include("global_settings.inc");
include("torture_cgi_names.inc");
include("misc_func.inc");
include("http.inc");

####

port = get_kb_item("Services/www");
if (!port) exit(0);

rep = "";

l = get_kb_list("torture_CGI/errors/"+port+"/*");
if (isnull(l)) exit(0);
l = sort(keys(l));

prev = NULL;
foreach k (l)
{
 if (k == prev) continue;
 prev = k;
 v = eregmatch(string: k, pattern: ".*/([^/]+)$");
 if (isnull(v)) continue;
 vul = v[1];
 n = get_kb_item(k);
 n = int(n);
 if (n > 0)
 {
   name = torture_cgi_name(code: vul);
   if (n == 1) rep = strcat(rep, "  - 1 error involving ", name, ' checks :\n');
   else if (n > 1) rep = strcat(rep, "  - ", n, " errors involving ", name, ' checks :\n');
   err_l = get_kb_list('torture_CGI/error_msg/'+port+'/'+vul);
   foreach m (err_l)
     rep = strcat(rep, '   . ', m, '\n');
 }
}

if (rep)
{
 if (http_is_dead(port: port))
   rep += '\nThis web server appears to be unresponsive now.\n';
 security_note(port: port, extra: strcat('\nNessus encountered :\n\n', rep));
}

