#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(52973);
 script_version("$Revision: 1.3 $");
 script_cvs_date("$Date: 2011/08/14 16:22:00 $");
 
 script_name(english:"Restricted Web Pages Detection");
 script_summary(english:"Look for restricted web pages");
 
 script_set_attribute(attribute:"synopsis", value:
"Restricted web pages were found." );
 script_set_attribute(attribute:"description", value:
"Nessus identified some web pages that cannot be reached when the user
is not logged in.  These pages will be used to maintain the web
session." );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/25");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi_func.inc");

port = get_http_port(default: 80, embedded: 1);

if (! get_kb_item("www/"+port+"/automatic_http_login"))
  exit(0, "'Automatic' HTTP login is not used for the web server listening on port "+port+".");

l = get_kb_list("www/"+port+"/content/extensions/*");
if (isnull(l))	# This is abnormal
  exit(1, "No web page was found on port "+port+".");

function escape_string()
{
  local_var	s, r, i, l, c;

  s = _FCT_ANON_ARGS[0];
  l = strlen(s);
  r = '';
  for (i = 0; i < l; i ++)
  {
    c = s[i];
    if (c == '.' || c == '\\' || c == '?' || c == '*' || 
        c == '[' || c == ']' || c =='(' || c == ')' || 
	c == '{' || c == '}')
      r += '\\';
    r += c;
    
  }
  return r;
}


l = make_list(l);

n_err = 0;
N=32;	# To avoid constant deconnection/reconnection
found = 0;
for (n = 0; ! isnull(l[n]); n += i)
{
  http_reauthenticate_if_needed(port:port , save_cookies: 0);

  res1 = make_list();
  # Read N pages while being authenticated
  for (i = 0; i < N && ! isnull(l[i+n]); i ++)
  {
    u = l[i+n];
    w = http_send_recv3(port:port, item: u, method:"GET", exit_on_fail: 0, follow_redirect: 0);
    res1[i] = w;
    if (isnull(w) && n_err ++ > 8) break;	# Stop if too many errors
  }

  clear_cookiejar();
  # Deconnect from the application and read the same pages again
  for (i = 0; i < N && ! isnull(l[i+n]); i ++)
  {
    u = l[i+n];
    if (isnull(res1[i])) continue;
    w = http_send_recv3(port:port, item: u, method:"GET", exit_on_fail: 0, follow_redirect: 0);
    if (isnull(w))
      if (n_err ++ > 8) exit(1, "Too many HTTP errors on port "+port+".");
    else
      continue;
    z = res1[i];
    # Do the responses differ?
    if (z[0] != w[0])	# Different HTTP code
    {
      v1 = eregmatch(string: z[0], pattern: "^HTTP/1\.[01] +([0-9]+)");
      v2 = eregmatch(string: w[0], pattern: "^HTTP/1\.[01] +([0-9]+)");
      replace_kb_item(name: "www/"+port+"/login_follow_30x", value: 0);
      replace_kb_item(name: "www/"+port+"/check_page", value: u);
      replace_kb_item(name: "www/"+port+"/regex_headers", value: TRUE);
      if (! isnull(v1) && ! isnull(v2))
      {
        code1 = v1[1]; code2= v2[2];
	if (code1 != code2)
	  pat = "^HTTP/1\.[01] +"+code1+"[^0-9]";
	else
	  pat = "^"+escape_string(chomp(z[0]));
	  
      }
      else
        pat = "^"+escape_string(chomp(z[0]));
      
      replace_kb_item( name: "www/"+port+"/check_regex", value: pat);
      security_note(port: port, extra: '\nThe following URL will be used :\n' +
build_url(port: port, qs: u) + 
'\nThe following pattern will be searched :\n' + pat + '\n');
      exit(0);
    }
    h1 = sanitize_utf16(body: z[2], headers: z[1]);
    h2 = sanitize_utf16(body: w[2], headers: w[1]);
    if (cmp_html(h1: h1, h2: h2) != 0)
    {
      # HTML pages differ, but this may be a dynamic page.
      # We look for some parts which will probably not change in such cases.
      foreach p (make_list('<title>', '<meta ', '<form '))
      {
        g = egrep(string: h2, pattern: p, icase: TRUE);
	foreach line (split(g, keep: 0))
	{
	  if (line >< h1) continue;
	  #
	  replace_kb_item(name: "www/"+port+"/login_follow_30x", value: 0);
	  replace_kb_item(name: "www/"+port+"/check_page", value: u);
	  replace_kb_item(name: "www/"+port+"/regex_headers", value: FALSE);
	  pat = "^"+escape_string(line);
	  replace_kb_item( name: "www/"+port+"/check_regex",
	  		   value: pat );

	  security_note(port: port, extra: 
'\nThe following URL will be used :\n' + build_url(port: port, qs: u) + '\n' +
'The following pattern will be search :\n' + pat + '\n');
	  exit(0);	  
	}
      }
    }
  }
  if (n_err > 8) exit(1, "Too many HTTP errors on port "+port+".");
}

exit(0, "No protected page was found on port "+port+".");
