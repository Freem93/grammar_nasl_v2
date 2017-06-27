#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84019);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/03/03 22:36:31 $");

  script_name(english:"WordPress Unsupported Version Detection");
  script_summary(english:"Checks for unsupported versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an unsupported version of WordPress.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
WordPress running on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.

Note that any new patches for previous versions are unofficial and are
not guaranteed to be continued in the future.");
  script_set_attribute(attribute:"see_also", value:"https://codex.wordpress.org/WordPress_Versions");
  # https://wordpress.org/support/topic/no-clearly-defined-eol?replies=1#post-7026986
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8179e12d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of WordPress that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("installed_sw/WordPress", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");


app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir         = install["path"];
version     = install["version"];
install_loc = build_url(port:port, qs:dir + "/query.cgi");

eol_dates = make_array(
  "^0\.",                "2003/10/11",
  "^1\.0($|[^0-9])",     "2004/03/11",
  "^1\.[12]($|[^0-9])",  "2004/12/15",
  "^1\.[345]($|[^0-9])", "2005/08/14",
  "^2\.0($|[^0-9])",     "2007/08/05",
  "^2\.1($|[^0-9])",     "2007/04/03",
  "^2\.2($|[^0-9])",     "2007/09/08",
  "^2\.3($|[^0-9])",     "2008/02/05",
  "^2\.[45]($|[^0-9])",  "2008/04/25",
  "^2\.6($|[^0-9])",     "2008/11/25",
  "^2\.7($|[^0-9])",     "2009/02/10",
  "^2\.8($|[^0-9])",     "2009/11/12",
  "^2\.9($|[^0-9])",     "2010/02/15",
  "^3\.0($|[^0-9])",     "2011/04/26",
  "^3\.1($|[^0-9])",     "2011/06/29",
  "^3\.2($|[^0-9])",     "2011/07/12",
  "^3\.3($|[^0-9])",     "2012/06/27",
  "^3\.4($|[^0-9])",     "2012/09/06",
  "^3\.5($|[^0-9])",     "2013/06/21",
  "^3\.6($|[^0-9])",     "2013/09/11",
  "^3\.7($|[^0-9])",     "2013/12/12", # date 3.8 released
  "^3\.8($|[^0-9])",     "2014/05/16", # date 3.9 released
  "^3\.9($|[^0-9])",     "2014/09/04", # date 4.0 released
  "^4\.0($|[^0-9])",     "2014/12/18", # date 4.1 released
  "^4\.1($|[^0-9])",     "2015/04/23", # date 4.2 released
  "^4\.2($|[^0-9])",     "2015/08/18", # date 4.3 released
  "^4\.3($|[^0-9])",     "2015/12/08", # date 4.4 released
  "^4\.4($|[^0-9])",     "2016/04/12", # date 4.5 released
  "^4\.5($|[^0-9])",     "2016/08/16", # date 4.6 released
  "^4\.6($|[^0-9])",     "2016/12/06"  # date 4.7 released
  # Dates : https://wordpress.org/about/roadmap/
  # https://wordpress.org/download/release-archive/ :
  # "None of these are safe to use, except the latest in the 4.7 series, which is actively maintained."
  # Above quote as of 16 JAN 2017
);

latest   = "4.7.x";
supported = TRUE;

foreach regex (keys(eol_dates))
{
  if (version =~ regex)
  {
    supported = FALSE;
    report_eol_date = eol_dates[regex];
    report_eol_url = "http://codex.wordpress.org/WordPress_Versions";
    break;
  }
}

if (!supported)
{
  register_unsupported_product(
    product_name : app,
    cpe_base     : "wordpress:wordpress",
    version      : version
  );

  report =
    '\n  URL                 : ' + install_loc +
    '\n  Installed version   : ' + version +
    '\n  End of support date : ' + report_eol_date +
    '\n  End of support URL  : ' + report_eol_url +
    '\n  Latest version      : ' + latest +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_WEB_APP_SUPPORTED, app, install_loc, version);
