#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71174);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 23:21:20 $");

  script_cve_id("CVE-2013-6786");
  script_bugtraq_id(63721);
  script_osvdb_id(99694);

  script_name(english:"RomPager HTTP Referer Header XSS");
  script_summary(english:"Tries to exploit XSS vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote RomPager HTTP server is affected by a cross-site scripting
vulnerability.  The server does not properly sanitize the referer header
value when generating a 404 error page.");
  # http://antoniovazquezblanco.github.io/docs/advisories/Advisory_RomPagerXSS.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54798697");
  script_set_attribute(attribute:"solution", value:"Upgrade to RomPager 4.51 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:allegro:rom_pager");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/allegro");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

app = "Allegro RomPager HTTP Server";

port = get_http_port(default:80, embedded:TRUE);
banner = get_http_banner(port:port, exit_on_fail:TRUE);
if ("RomPager" >!< banner) audit(AUDIT_NOT_LISTEN, app, port);

url = "/" + rand_str(length:16);

xss = '"><script>alert("XSS")</script>';

res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : url,
  fetch404     : TRUE,
  add_headers  : make_array('Referer', xss),
  exit_on_fail : TRUE
);

if (
  "The requested URL '" + url + "' was not found on the RomPager server." >< res[2] &&
  'Return to <A HREF="' + xss + '">last page</A><p>' >< res[2]
)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    last_req = http_last_sent_request();
    report =
      '\n' + 'Nessus was able to verify the vulnerability exists with the' +
      '\n' + 'following HTTP request :' +
      '\n' +
      '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + 
      '\n' + chomp(last_req) + 
      '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + 
      '\n';

    if (report_verbosity > 1)
    {
      response_body = res[2];
      report +=
        '\n' + 'Here is the HTTP response body :' +
        '\n' +
        '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + 
        '\n' + chomp(response_body) + 
        '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + 
        '\n';
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, app, port);
