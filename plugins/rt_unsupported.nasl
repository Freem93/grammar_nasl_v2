#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83141);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 23:21:20 $");

  script_name(english:"Request Tracker Unsupported Version Detection");
  script_summary(english:"Checks the version of Request Tracker.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of Request Tracker.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Request Tracker on the
remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.bestpractical.com/rt/release-policy.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to a version of Request Tracker that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bestpractical:rt");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("rt_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("installed_sw/RT", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

product = "RT";
get_install_count(app_name:product, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(app_name:product, port:port, exit_if_unknown_ver:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = install['version'];
path    = install['path'];
install_url = build_url(port:port, qs:path + "/");

supported_versions = '4.0.x / 4.2.x';

ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

# Versions 4.1.x are unreleased development versions
# so comparing for a version below 4 is sufficient
# at this point in time
if (ver[0] < 4)
{
  register_unsupported_product(
    product_name : product,
    version      : version,
    cpe_base     : "cpe:/a:bestpractical:rt"
  );

  if (report_verbosity > 0)
  {
    report =
      '\n  Path               : ' + install_url +
      '\n  Installed version  : ' + version +
      '\n  Supported versions : ' + supported_versions +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, product, install_url, version);
