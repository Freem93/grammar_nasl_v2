#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81180);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/02 23:36:51 $");

  script_name(english:"Atmail Webmail Unsupported Version Detection");
  script_summary(english:"Checks for unsupported versions.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is running an unsupported version of Atmail Webmail.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Atmail
Webmail on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.atmail.com/");
  script_set_attribute(attribute:"solution", value:"Upgrade to an actively maintained version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atmail:atmail");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("atmail_webmail_detect.nasl");
  script_require_keys("www/atmail_webmail");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);
install = get_install_from_kb(appname:'atmail_webmail', port:port, exit_on_fail:TRUE);

dir = install['dir'];
display_version = install['ver'];
# Get normalized version for check
kb_dir = str_replace(string:dir, find:"/", replace:"\");
version = get_kb_item_or_exit('www/'+port+'/atmail_webmail_normalized_ver/'+kb_dir+'/'+display_version);
install_url = build_url(port:port, qs:dir);

if (version == UNKNOWN_VER || isnull(version))
  audit(AUDIT_UNKNOWN_WEB_APP_VER, "Atmail Webmail", install_url);

eol_dates = make_array(
  "^[0-5]\.", "2011/01/01",
  "^6\."    , "2014/06/30"
);
eol_urls  = make_array(
  "^[0-5]\.", "https://www.atmail.com/blog/atmail-57-released",
  "^6\."    , "https://help.atmail.com/hc/en-us/articles/203132114-Renewal-Policy"
);

latest   = "7.x";
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
    product_name : "Atmail Webmail",
    cpe_base     : "atmail:atmail_webmail",
    version      : display_version
  );

  if (report_verbosity > 0)
  {
    report =
      '\n  URL                 : ' + install_url +
      '\n  Installed version   : ' + display_version +
      '\n  End of support date : ' + report_eol_date +
      '\n  End of support URL  : ' + report_eol_url +
      '\n  Latest version      : ' + latest +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Atmail Webmail", install_url, display_version);
