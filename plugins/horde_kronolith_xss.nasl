#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61449);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id("CVE-2012-6620");
  script_bugtraq_id(53731);
  script_osvdb_id(81878);

  script_name(english:"Horde Kronolith js/kronolith.js Multiple View XSS");
  script_summary(english:"Checks kronolith.js for vulnerable code");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Kronolith installed on the remote host is affected by
multiple cross-site scripting vulnerabilities because it fails to
sanitize user input to the 'tasks' and 'search' views upon submission
to the js/kronolith.js script. 

An attacker may be able to leverage these vulnerabilities to inject
arbitrary HTML and script code into a user's browser to be executed
within the security context of the affected site.");
  script_set_attribute(attribute:"see_also", value:"https://lists.horde.org/archives/announce/2012/000766.html");
  script_set_attribute(attribute:"see_also", value:"http://bugs.horde.org/ticket/11189");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 3.0.17 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:horde:kronolith");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("horde_kronolith_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/horde_kronolith", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname      : "horde_kronolith",
  port         : port,
  exit_on_fail : TRUE
);
dir = install["dir"];

url = dir + "/js/kronolith.js";
res = http_send_recv3(
  method       : "GET",
  item         : url,
  port         : port,
  exit_on_fail : TRUE
);

body = res[2];
count = 0;
if ("* kronolith.js - Base application logic" >< body)
{
  patch = ".escapeHTML()";

  # set strings to check for
  lines = make_list(
    "message\.insert\(new Element\('br'\)\)\.insert\(alarm\.params\.notify\.subtitle\);",
    "return this\.setTitle\(Kronolith\.text\.searching\.interpolate\(\{ term: data \}\)\)",
    "col\.insert\(new Element\('span', \{ className: 'kronolithInfo' \}\)\.update\(task\.value\.sd",
    "\.insert\(calendar\.name",
    "\$\('kronolithEventTargetRO'\)\.update\(Kronolith\.conf\.calendars\[ev\.ty\]\[ev\.c\]\.name"
  );

  need_patch = "";
  foreach line (lines)
  {
    check = egrep(pattern:line, string:body);
    if (check && patch >!< check)
    {
      count++;
      need_patch += (check + "---");
    }
  }
}

if (count == 0)
{
  loc = build_url(port:port, qs:dir + "/");
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Kronolith", loc);
}

set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n' + 'Nessus was able to verify the issue by examining the source of' +
    '\n' + 'js/kronolith.js using the following URL : ' +
    '\n' +
    '\n  ' + build_url(port:port, qs:url) +
    '\n';

  if (report_verbosity > 1)
  {
    snip = crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
    output = ereg_replace(pattern:"---", replace:snip, string:need_patch);

    report +=
      '\nNessus determined the following vulnerable code sequences have not' +
      '\nbeen remedied in this version of Kronolith : ' +
      '\n' +
      '\n' + snip + output +
      '\n';
  }
  security_warning(port:port, extra:report);
  exit(0);
}
else security_warning(port);

