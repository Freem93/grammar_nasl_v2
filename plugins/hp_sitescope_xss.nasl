#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53622);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/14 03:46:10 $");

  script_cve_id("CVE-2011-1726");
  script_bugtraq_id(47554);
  script_osvdb_id(72060);
  script_xref(name:"Secunia", value:"44322");

  script_name(english:"HP SiteScope XSS");
  script_summary(english:"Checks for cross-site scripting.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a version of HP SiteScope that is
vulnerable to a cross-site scripting attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"There is a cross-site scripting vulnerability in this installation of
HP SiteScope that may allow an attacker to execute arbitrary script
code in the browser of an unsuspecting user.  Such script code could
steal authentication credentials and be used to launch other attacks."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d008b65d");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 11.1 and install hotfix SS1110110412.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/02");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:mercury_sitescope");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("hp_sitescope_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/sitescope");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("url_func.inc");
include("webapp_func.inc");

# Get details of SiteScope install.
port = get_http_port(default:8080);
install = get_install_from_kb(appname:"sitescope", port:port, exit_on_fail:TRUE);
dir = install["dir"];

# Create a query to trigger the vulnerability.
xss = "<script>alert('" + SCRIPT_NAME + unixtime() + "');</script>";
exploited = test_cgi_xss(
  port        : port,
  dirs        : make_list(dir),
  add_headers : make_array("Accept-Language", "en-us"),
  cgi         : "/jsp/hosted/HostedSiteScopeMessage.jsp",
  qs          : "messageKey=" + urlencode(str:xss),
  pass_str    : "???en_US." + xss + "???",
  ctrl_re     : '<td[^>]+id="m5_content">'
);

if (!exploited)
{
  url = build_url(qs:dir + '/', port:port);
  exit(0, "The HP SiteScope install at " + url + " is not affected.");
}
