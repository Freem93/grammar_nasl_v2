#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78912);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_name(english:"Joomla! Unsupported Version Detection");
  script_summary(english:"Checks for unsupported Joomla! versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of Joomla!.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Joomla! on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://developer.joomla.org/news/586-joomla-development-strategy.html");
  script_set_attribute(attribute:"see_also", value:"https://docs.joomla.org/Category:Version_History");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Joomla! that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_require_keys("installed_sw/Joomla!", "www/PHP");
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

dir = install['path'];
version = install['version'];
install_loc =  build_url(port:port, qs:dir);

# Supported versions:
#  - 3.7 is the latest available (and only supported) release branch.
# There is currently no separate LTS release branch
latest = '3.7';

# Elements in this list can contain text like "2.5.x LTS". The only requirement
# is the first character must be the same as the major version number
supported_versions = make_list(
  '3.7.x'
);

if (
  # next time Joomla has an LTS branch, the check for it must be included here. e.g. for 2.5.x LTS: version !~ "^2\.5\."
  ver_compare(ver:version, fix:latest, strict:FALSE) == -1
)
{
  foreach supported_ver (supported_versions)
  {
    # assume patches will only be backported from/to the same major version
    if (supported_ver[0] == version[0] && report_paranoia < 2) audit(AUDIT_PARANOID);
  }

  register_unsupported_product(product_name:'Joomla',
                               version:version, cpe_base:"joomla:joomla\!");
  report =
    '\n  URL                : ' + install_loc +
    '\n  Installed version  : ' + version +
    '\n  Supported versions : ' + join(supported_versions, sep:' / ') +
    '\n';

  security_report_v4(
    port:port,
    extra:report,
    severity:SECURITY_HOLE);
}
else audit(AUDIT_NOT_INST, "an unsupported version of Joomla!");
