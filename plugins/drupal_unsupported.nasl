#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89684);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/03/04 20:33:22 $");

  script_name(english:"Drupal Unsupported Version Detection");
  script_summary(english:"Checks for unsupported versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an unsupported version of Drupal.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Drupal running on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.

Note that several vendors provide Long Term Support (LTS) for Drupal.
If this version of Drupal is an LTS install, consider this finding to
be a false positive.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/forum/8");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/d6lts");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Drupal that is currently supported.

Alternatively, contact one of the Long Term Support vendors for
options.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

dir     = install["path"];
version = install["version"];
url = build_url(port:port, qs:dir);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

eol_dates = make_array(
  "^[0-4]\.",         "2011/01/21",
  "^5($|[^0-9])",     "2011/01/21",
  "^6($|[^0-9])",     "2016/02/24"
);
eol_urls = make_array(
  "^[0-4]\.",         "",
  "^5($|[^0-9])",     "https://www.drupal.org/node/1027214",
  "^6($|[^0-9])",     "https://www.drupal.org/drupal-6-eol"
);

latest   = "7.x / 8.x";
supported = TRUE;

foreach regex (keys(eol_dates))
{
  if (version =~ regex)
  {
    supported = FALSE;
    report_eol_date = eol_dates[regex];
    if (empty_or_null(eol_urls[regex]))
      report_eol_url = "https://www.drupal.org/forum/8";
    else
      report_eol_url = eol_urls[regex];

    break;
  }
}

if (!supported)
{
  register_unsupported_product(
    product_name : app,
    cpe_base     : "drupal:drupal",
    version      : version
  );

  security_report_v4(
    port:port,
    severity: SECURITY_HOLE,
    extra:
      '\n  URL                 : ' + url +
      '\n  Installed version   : ' + version +
      '\n  End of support date : ' + report_eol_date +
      '\n  End of support URL  : ' + report_eol_url +
      '\n  Latest version      : ' + latest +
      '\n'
  );
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);
