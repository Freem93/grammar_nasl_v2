#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59171);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id("CVE-2012-1190");
  script_bugtraq_id(52857);
  script_osvdb_id(79392);

  script_name(english:"phpMyAdmin Replication Setup js/replication.js Database Name XSS");
  script_summary(english:"Checks for a vulnerable phpMyAdmin Version");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote web server hosts a PHP application that is affected by a
cross-site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"According to its self-identified version number, the phpMyAdmin
install hosted on the remote web server is affected by a cross-site
scripting vulnerability. 

The vulnerability is in the replication-setup functionality in 
js/replication.js in phpMyAdmin 3.4.x before 3.4.10.1, which allows 
user-assisted remote attackers to inject arbitrary web script or HTML 
via a crafted database name.");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2012-1.php"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to phpMyAdmin 3.4.10.1 or later or apply the patch from the
referenced link."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/phpMyAdmin", "Settings/ParanoidReport");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:"phpMyAdmin", port:port, exit_on_fail:TRUE);
dir = install['dir'];
version = install['ver'];
location = build_url(qs:dir, port:port);
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "phpMyAdmin", location);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] == 3 && ver[1] == 4 && ver[2] == 10 && ver[3] < 1) ||
  (ver[0] == 3 && ver[1] == 4 && ver[2] < 10)
)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +location+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 3.4.10.1\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "phpMyAdmin", location, version);
