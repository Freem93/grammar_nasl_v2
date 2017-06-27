#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84018);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/08/01 16:02:37 $");

  script_name(english:"ManageEngine Applications Manager Unsupported Version Detection");
  script_summary(english:"Checks for unsupported versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an unsupported version of ManageEngine
Applications Manager.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the ManageEngine Applications
Manager installed on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.manageengine.com/products/applications_manager/eol.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a supported version of ManageEngine Applications Manager.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:manageengine:applications_manager");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("manageengine_applications_manager_detect.nasl");
  script_require_keys("installed_sw/ManageEngine Applications Manager");
  script_require_ports("Services/www", 9090);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "ManageEngine Applications Manager";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:9090);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
ver = install['version'];
install_url = build_url(port:port, qs:dir);

latest = "12.x";

eol_dates = make_array(
  "^[0-5]\.", "Unknown. Refer to vendor",
  "^6\.", "2008/03/01",
  "^7\.", "2009/06/24",
  "^8\.", "2010/09/13",
  "^9\.", "2012/07/03",
  "^10\.", "2014/08/17",
  "^11\.", "2015/12/28"
#  "^12\.", "2018/04/20"
);

unsupported = FALSE;

foreach v (keys(eol_dates))
{
  if (ver =~ v)
  {
    unsupported = TRUE;
    break;
  }
}

if (unsupported)
{
  register_unsupported_product(
    product_name : app,
    version      : ver,
    cpe_base     : "manageengine:applications_manager");

  report =
    '\n  Product             : ' + app +
    '\n  URL                 : ' + install_url +
    '\n  Installed version   : ' + ver +
    '\n  End of support date : ' + eol_dates[v] +
    '\n  Latest version      : ' + latest;
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
  exit(0);
}
else
  exit(0, "The " + app + " install at " + install_url + " is version " + ver + " and is still supported.");
