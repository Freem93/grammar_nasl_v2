#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57981);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/03/04 16:15:43 $");

  script_cve_id("CVE-2012-0084");
  script_bugtraq_id(51454);
  script_osvdb_id(78404);

  script_name(english:"Oracle WebCenter Content idc/idcplg Multiple Parameter XSS");
  script_summary(english:"Tests for cross-site scripting in /idc/idcplg");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a script that is prone to a reflected
cross-site scripting attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Oracle WebCenter Content script '/idc/idcplg' contains several
parameters that are incorrectly filtered, including 'sltPageTitle' and
'redirectPageTitle'.  This makes the WebCenter Content install
susceptible to a reflected cross-site scripting attack.

By tricking someone into clicking on a specially crafted link, an
attacker may be able exploit this to inject arbitrary HTML and script
code in a user's browser to be executed within the security context of
the affected site."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f19d081");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/topics/security/cpujan2012-366304.html");
  script_set_attribute(
    attribute:"solution",
    value:
"See the Oracle advisory for information on obtaining and applying bug
fix patches."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("oracle_webcenter_content_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("installed_sw/Oracle WebCenter Content");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app_name = "Oracle WebCenter Content";

get_install_count(app_name:app_name, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(app_name:app_name, port:port);

dir = install['path'];

install_url = build_url(port: port, qs:dir);

xss = "IdcService=GET_PORTAL_PAGE&Action=GetTemplatePage&Page=PNE_LIST_TEMPLATES_PAGE&sltClass=searchResults&sltPageTitle=%3Cimg/src=%27.%27/onerror=%27alert%28%22" + SCRIPT_NAME + "%22%29%27%3E";
res = test_cgi_xss(
  port:port,
  cgi:'/idcplg',
  qs:xss,
  pass_str:'inline;"><img/src=\'.\'/onerror=\'alert("' + SCRIPT_NAME + '")\'>',
  ctrl_re:'<meta name="GENERATOR" content="Idc Content',
  dirs:make_list(dir)
);

if (res == 0) audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url);
