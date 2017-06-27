#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54603);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/09/24 23:21:20 $");

  script_cve_id("CVE-2011-0613");
  script_bugtraq_id(47839);
  script_osvdb_id(72317);
  script_xref(name:"Secunia", value:"44480");

  script_name(english:"Adobe RoboHelp FlashHelp Unspecified XSS (APSB11-09) (uncredentialed check)");
  script_summary(english:"Checks for unpatched files");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The published RoboHelp project on the remote host contains a
cross-site scripting vulnerability in its wf_status.htm and wf_topicfs
files. An attacker may be able to leverage this issue to execute
arbitrary script code in the browser of an authenticated user in the
context of the affected site and to steal cookie-based authentication
credentials."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-09.html");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in the vendor advisory above.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/20");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:robohelp");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("webmirror.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

# Get details of the web server.
port = get_http_port(default:80);
htms = get_kb_list("www/" + port + "/content/extensions/htm");

# We cannot directly test the XSS since it's created by JavaScript
# document.write() calls. So we detect the generating code itself.
vuln = FALSE;
foreach htm (htms)
{
  # Skip pages that don't have the filename we're looking for.
  if (htm !~ "wf_status.htm$") continue;

  # Try to pull down one of the vulnerable files.
  res = http_send_recv3(
    method       : "GET",
    item         : htm,
    port         : port,
    exit_on_fail : TRUE
  );

  # Ensure that the HTML file has a couple things in it that are likely to be
  # unique to the vulnerable file we're looking for.
  if (
    'sHtml += "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";' >!< res[2] ||
    'strObject += "<PARAM NAME=\'movie\' VALUE=\'"+status_swf+"\'>";' >!< res[2]
  ) continue;

  vuln = TRUE;
  break;
}
if (!vuln) exit(0, "No vulnerable RoboHelp installs were detected.");

set_kb_item(name:"www/"+port+"/XSS", value:TRUE);

if (report_verbosity > 0)
{
  xss = "?gsStatusSwf='></embed><script>alert('XSS');</script>";
  report =
    '\nNessus was able to detect the issue, but could not directly test for it.' +
    '\nWeb browsers that support JavaScript can trigger the issue by using the' +
    '\nfollowing request :' +
    '\n' +
    '\n  ' + build_url(port:port, qs:htm + xss) +
    '\n';

  security_warning(port:port, extra:report);
}
else security_warning(port);
