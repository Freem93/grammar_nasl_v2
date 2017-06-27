#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78088);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/05/19 13:58:06 $");

  script_cve_id("CVE-2014-7228", "CVE-2014-7229");
  script_bugtraq_id(70199, 70201);
  script_osvdb_id(112407, 112408);
  script_xref(name:"EDB-ID", value:"35033");

  script_name(english:"Joomla! 2.5.x < 2.5.26 / 3.x < 3.2.6 / 3.3.x < 3.3.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Joomla!.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Joomla!
installation running on the remote web server is 2.5.x prior to
2.5.26, 3.x prior to 3.2.6, or 3.3.x prior to 3.3.5. It is, therefore,
affected by multiple vulnerabilities :

  - A security bypass vulnerability exists in the
    restore.php script during the extraction of backup
    archives or Joomla! update packages. An unauthenticated,
    remote attacker can exploit this, via a command message
    that extracts a crafted archive, to bypass command
    execution security restrictions and execute arbitrary
    code with the same privileges as the web server.
    (CVE-2014-7228)

  - An unspecified flaw exists due to inadequate checking
    that allows an unauthenticated, remote attacker to cause
    a denial of service condition. (CVE-2014-7229)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.joomla.org/announcements/release-news/5566-joomla-2-5-26-released.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80de2915");
  # https://www.joomla.org/announcements/release-news/5567-joomla-3-3-5-released.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?47bbcae3");
  script_set_attribute(attribute:"see_also", value:"https://developer.joomla.org/security/595-20140903.html");
  script_set_attribute(attribute:"see_also", value:"https://developer.joomla.org/security/596-20140904.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 2.5.26 / 3.2.6 / 3.3.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Joomla Akeeba Kickstart Unserialize Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_require_keys("installed_sw/Joomla!", "www/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Joomla!";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = install['version'];
install_loc =  build_url(port:port, qs:install['path']);

fix = "2.5.26 / 3.2.6 / 3.3.5";

# Check granularity
if (
  version =~ "^2(\.5)?$" ||
  version =~ "^3(\.[0-3])?$"
) audit(AUDIT_VER_NOT_GRANULAR, app, port, version);

# Versions 2.5.x < 2.5.26 / 3.x < 3.2.6 / 3.3.x < 3.3.5 are vulnerable
# (There are Alpha versions of some builds)
if (
  version =~ "^2\.5\.([0-9]|1[0-9]|2[0-5])([^0-9]|$)" ||
  version =~ "^3\.[01]([^0-9]|$)" ||
  version =~ "^3\.2\.[0-5]([^0-9]|$)" ||
  version =~ "^3\.3\.[0-4]([^0-9]|$)"
)
{
   order = make_list("URL", "Installed version", "Fixed version");
  report = make_array(
    order[0], install_loc,
    order[1], version,
    order[2], fix
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
