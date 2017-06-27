#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84292);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/09/26 19:18:36 $");

  script_cve_id(
    "CVE-2015-3231",
    "CVE-2015-3232",
    "CVE-2015-3233",
    "CVE-2015-3234"
  );
  script_bugtraq_id(75284, 75286, 75287, 75294);

  script_name(english:"Drupal 7.x < 7.38 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Drupal.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running a version of Drupal that is 7.x prior
to 7.38. It is, therefore, potentially affected by the following
vulnerabilities :

  - An open redirect vulnerability exists due to improper
    validation of user-supplied input to the 'destinations'
    parameter in the Field UI module. A remote attacker can
    exploit this issue, via a specially crafted URL, to
    redirect users to a third-party website. (CVE-2015-3231)

  - An open redirect vulnerability exists due to improper
    validation of URLs prior displaying their contents via
    the Overlay module on administrative pages.
    (CVE-2015-3232)

  - An information disclosure vulnerability exists due to a
    flaw in the render cache system. An attacker can exploit
    this flaw to view private content of arbitrary users.
    (CVE-2015-3233)

  - A security bypass vulnerability exists due to a flaw in
    the OpenID module. A remote attacker can exploit this
    flaw to log in as other users, including administrators.
    Note that victims must have an existing OpenID account
    from a particular set of OpenID providers including,
    but not limited to, Verisign, LiveJournal, or
    StackExchange. (CVE-2015-3234)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/SA-CORE-2015-002");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/drupal-7.38-release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 7.38 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/Drupal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Drupal";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
url = build_url(qs:dir, port:port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version =~ "^7\.([0-9]|[1-2][0-9]|3[0-7])($|[^0-9]+)")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.38' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);
