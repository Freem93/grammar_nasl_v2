#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (! defined_func("zlib_compress")) exit(1);

if (description)
{
 script_id(56818);
 script_version("$Revision: 1.8 $");
 script_cvs_date("$Date: 2017/01/24 16:25:46 $");

 script_name(english: "CGI Generic Cross-Site Request Forgery Detection (potential)");
 script_summary(english: "Check for random tokens in CGIs.");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server might be prone to cross-site request forgery
attacks.");
 script_set_attribute(attribute:"description", value:
"Nessus has found HTML forms on the remote web server. Some CGI scripts
do not appear to be protected by random tokens, a common
anti-cross-site request forgery (XSRF) protection. The web application
might be vulnerable to XSRF attacks. Note that :

  - Nessus did not exploit the flaw.
  - Nessus cannot identify sensitive actions; for example, on an
    online bank, consulting an account is less sensitive than
    transferring money.

You will need to audit the source of the CGI scripts and check if they
are actually affected.");
 script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Cross-site_request_forgery");
 script_set_attribute(attribute:"solution", value:
"Restrict access to the vulnerable application. Contact the vendor for
a patch or upgrade.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
 script_cwe_id(
   352, # Cross-Site Request Forgery CSRF
   716, # OWASP Top Ten 2007 Category A5 - Cross Site Request Forgery CSRF
   751, # 2009 Top 25 - Insecure Interaction Between Components
   801, # 2010 Top 25 - Insecure Interaction Between Components
   814, # OWASP Top Ten 2010 Category A5 - Cross-Site Request ForgeryCSRF
   928, # Weaknesses in OWASP Top Ten 2013
   936  # OWASP Top Ten 2013 Category A8 - Cross-Site Request Forgery CSRF
 );

 script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/17");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

 script_dependencie(
  "http_version.nasl",
  "webmirror.nasl",
  "web_app_test_settings.nasl",
  "pci_compliance_settings.nasl"
 );
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/PCI_DSS");

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

include("torture_cgi_func.inc");
include("url_func.inc");

if (! get_kb_item("Settings/PCI_DSS") || !get_kb_item("Settings/enable_web_app_tests" ))
  exit(0, 'This script only runs in PCI DSS mode with Web App Tests enabled.');

port = get_http_port(default: 80);

if ( islocalhost() )
{
 xmlrpc_port = int(get_preference("xmlrpc_listen_port"));
 if ( xmlrpc_port == port ) exit(0);
}

cgi_l = get_cgi_list(port: port);
if (max_index(cgi_l) == 0) exit(0, "No CGI on port "+port+".");

function random_val()
{
  local_var	v, c;

  v = _FCT_ANON_ARGS[0];
  if (strlen(v) < 16) return 0;
  c = zlib_compress(data: v, level: 9);
  if (strlen(c) < 16) return 0;
  return 1;
}

unprotected_cgis = make_list();

foreach cgi(cgi_l)
{
  # Verify that we can reach the cgi being tested
  res = http_send_recv3(
    method : "GET",
    item   : cgi,
    port   : port,
    exit_on_fail :FALSE
  );
  if (res[0] =~ "(403|404|500)") continue;

  debug_print('CGI=', cgi, '\n');
  protected = 0;
  args_l = get_cgi_arg_list(port: port, cgi: cgi);
  if (max_index(args_l) == 0) continue;
  foreach arg (args_l)
  {
    debug_print('CGI=', cgi, '\t', 'ARG=', arg, '\n');
    l = get_cgi_arg_val_list(port: port, cgi: cgi, arg: arg, fill: 0);
    foreach v (l)
    {
      # No need to call replace_cgi_args_token here
      debug_print('CGI=', cgi, '\t', 'ARG=', arg, '\tVAL=', v, '\n');
      if (random_val(v))
      {
        protected = 1;
	break;
      }
    }
    if (protected) break;
  }
  if (! protected) unprotected_cgis = make_list(unprotected_cgis, cgi);
}

if (max_index(unprotected_cgis) == 0)
 exit(0, 'No unprotected CGI scripts were found hosted by the web server listening on port '+port+'.');

report = '\nThe following CGIs are not protected by a random token :\n';

foreach cgi (unprotected_cgis) report = strcat(report, cgi, '\n');

set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);
security_warning(port:port, extra:report);
