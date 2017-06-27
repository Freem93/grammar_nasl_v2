#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81554);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/07/29 16:26:29 $");

  script_name(english:"Bugzilla Unsupported Version Detection");
  script_summary(english:"Checks for unsupported versions.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is running an unsupported version of Bugzilla.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Bugzilla
running on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.bugzilla.org/releases/");
  script_set_attribute(attribute:"solution", value:"Upgrade to an actively maintained version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:bugzilla");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("bugzilla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("installed_sw/Bugzilla", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = "Bugzilla";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);
dir = install["path"];
version = install["version"];

install_loc = build_url(port:port, qs:dir + "/query.cgi");

eol_dates = make_array(
  "^2\.([0-9]|1[0-6])($|[^0-9])", "2006/04/22",
  "^2\.18($|[^0-9])", "2007/05/09",
  "^2\.20($|[^0-9])", "2008/11/29",
  "^2\.22($|[^0-9])", "2009/07/28",
  "^3\.0($|[^0-9])", "2010/04/14",
  "^3\.2($|[^0-9])", "2011/02/15",
  "^3\.4($|[^0-9])", "2012/02/22",
  "^3\.6($|[^0-9])", "2013/05/22",
  "^4\.0($|[^0-9])", "2015/07/07",
  "^4\.2($|[^0-9])", "2015/12/22"
);
eol_urls  = make_array(
  "^2\.([0-9]|1[0-6])($|[^0-9])", "https://www.bugzilla.org/status/2006-04-22.html",
  "^2\.18($|[^0-9])", "https://www.bugzilla.org/status/2007-05-09.html",
  "^2\.20($|[^0-9])", "https://www.bugzilla.org/status/2008-11-29.html",
  "^2\.22($|[^0-9])", "http://www.bugzilla.org/news/#release34",
  "^3\.0($|[^0-9])", "http://www.bugzilla.org/news/#release36",
  "^3\.2($|[^0-9])", "http://www.bugzilla.org/news/#release40",
  "^3\.4($|[^0-9])", "http://www.bugzilla.org/news/#release42",
  "^3\.6($|[^0-9])", "http://www.bugzilla.org/news/#release44",
  "^4\.0($|[^0-9])", "http://www.bugzilla.org/news/#release50",
  "^4\.2($|[^0-9])", "http://www.bugzilla.org/news/#release502"
);

latest   = "4.4.x / 5.0.x / 5.1.x";
supported = TRUE;

foreach regex (keys(eol_dates))
{
  if (version !~ regex) continue;

  supported = FALSE;
  report_eol_date = eol_dates[regex];

  if (!isnull(eol_urls[regex]))
    report_eol_url = eol_urls[regex];
  else
    report_eol_url = "n/a";
}

if (!supported)
{
  register_unsupported_product(
    product_name : "Bugzilla",
    cpe_base     : "mozilla:bugzilla",
    version      : version
  );

  if (report_verbosity > 0)
  {
    report =
      '\n  URL                 : ' + install_loc +
      '\n  Installed version   : ' + version +
      '\n  End of support date : ' + report_eol_date +
      '\n  End of support URL  : ' + report_eol_url +
      '\n  Latest version      : ' + latest +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Bugzilla", install_loc, version);
