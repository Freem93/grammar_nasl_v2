#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58582);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id("CVE-2012-4580");
  script_bugtraq_id(52487);
  script_osvdb_id(80138);
  script_xref(name:"MCAFEE-SB", value:"SB10020");

  script_name(english:"McAfee WebShield UI ProcessTextFile bodyStyle Parameter XSS (SB10020)");
  script_summary(english:"Attempted reflected XSS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application hosted on the remote web server has a cross-site
scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of WebShield UI hosted on the remote web server has a
reflected cross-site scripting vulnerability.  Input to the 'bodyStyle'
parameter of ProcessTextFiles is not properly sanitized.

A remote attacker could exploit this by tricking a user into requesting
a maliciously crafted URL, resulting in arbitrary script code execution.

This application has several other vulnerabilities, though Nessus has
not checked for those issues."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/522117");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10020");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch specified in the McAfee advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:webshield");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_webshield_web_ui_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/mcafee_webshield");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include('global_settings.inc');
include('misc_func.inc');
include('http.inc');
include('webapp_func.inc');
include('url_func.inc');

port = get_http_port(default:443);
install = get_install_from_kb(appname:'mcafee_webshield', port:port, exit_on_fail:TRUE);

dir = install['dir'] + '/cgi-bin';
cgi = '/ProcessTextFile';
xss = "'><script>alert(/" + SCRIPT_NAME + "/)</script>";
encoded_xss = urlencode(str:xss);
qs = 'file=BannerGui&bodyStyle=' + xss;
expected_output = "style='" + xss + "'>";

exploited = test_cgi_xss(
  port:port,
  dirs:make_list(dir),
  cgi:cgi,
  qs:qs,
  pass_str:expected_output,
  ctrl_re:'function bannerLoaded'
);

if (!exploited)
  exit(0, build_url(qs:dir+cgi, port:port) + " is not affected.");
