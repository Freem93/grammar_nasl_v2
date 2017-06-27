#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78917);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/08/01 19:58:58 $");

  script_name(english:"SolarWinds Log and Event Manager Unsupported Version Detection");
  script_summary(english:"Checks for unsupported versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an unsupported version of SolarWinds Log
and Event Manager.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of the
SolarWinds Log and Event Manager on the remote host is no longer
supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # https://support.solarwinds.com/Success_Center/Customer_Service/Currently_supported_software_versions#Log_.26_Event_Manager
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?022416ae");
  script_set_attribute(attribute:"solution", value:"Upgrade to an actively maintained version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:log_and_event_manager");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("solarwinds_lem_detect.nbin");
  script_require_keys("installed_sw/SolarWinds Log and Event Manager");
  script_require_ports("Services/www", 8080, 8443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:8080);

app  = "SolarWinds Log and Event Manager";
install = get_single_install(app_name: app, port: port, exit_if_unknown_ver:TRUE);

dir        = install['path'];
version    = install['version'];
version_ui = install['display_version'];

install_url = build_url(port:port, qs:dir);

latest   = "6.2.x";
cutoff   = "6.1";
eol_date = "2015/05/03";

if (ver_compare(ver:version, fix:cutoff, strict:FALSE) < 0)
{
  register_unsupported_product(product_name:"SolarWinds Log and Event Server",
                              cpe_base:"solarwinds:log_and_event_manager", version:version_ui);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL                 : ' + install_url +
      '\n  Installed version   : ' + version_ui +
      '\n  End of support date : ' + eol_date +
      '\n  Latest version      : ' + latest +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "The " + app + " " + version_ui + " install at " + install_url + " is still supported.");
