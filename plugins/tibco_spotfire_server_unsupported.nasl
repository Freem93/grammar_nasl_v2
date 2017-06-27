#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78394);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/04 19:51:44 $");

  script_name(english:"TIBCO Spotfire Server Unsupported Version Detection");
  script_summary(english:"Checks for unsupported versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an unsupported version of TIBCO Spotfire
Server.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
TIBCO Spotfire Server running on the remote host is no longer
supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://supportinfo.tibco.com/docs/TIBCOEndofSupportInformation.pdf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of TIBCO Spotfire Server that is currently
supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tibco:spotfire_server");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("tibco_spotfire_server_detect.nbin");
  script_require_keys("installed_sw/TIBCO Spotfire Server");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");

port = get_http_port(default:80);

app_name = "TIBCO Spotfire Server";
install = get_single_install(app_name:app_name, port:port, exit_if_unknown_ver:TRUE);

url = build_url(port:port, qs:install['path']);
version = install['version'];

latest = "7.6.x / 7.5.x / 7.0.x / 6.5.x";

eol_dates = make_array(
  "^6\.0\.", "2016/06/12",
  "^5\.5\.", "2015/12/12",
  "^5\.0\.", "2015/06/13",
  "^4\.5\.", "2014/12/13",
  "^3\.3\.", "2014/06/12",
  "^3\.2\.", "2013/07/21",
  "^3\.1\.", "2013/07/21",
  "^3\.0\.", "2013/07/21"
);

ext_dates = make_array(
  "^6\.0\.", "2017/06/12",
  "^6\.5\.", "2018/03/31"
);

note = '';

foreach v (keys(ext_dates))
{
  if (version =~ v)
  {
    set_kb_item(
      name:"www/"+port+"/"+app_name+"/extended_support",
      value:app_name + " support ends on " + ext_dates[v]
    );
    if (report_paranoia < 2)
      exit(0, app_name + " is an extended support release.");
  }
}

eol_date = NULL;
foreach v (keys(eol_dates))
{
  if (version =~ v)
  {
    eol_date = eol_dates[v];
    break;
  }
}

if (isnull(eol_date)) exit(0, "The " + app_name + " install at " + url + " is still supported.");

register_unsupported_product(
  product_name : app_name,
  cpe_base     : "tibco:spotfire_server",
  version      : version
);

report =
  '\n  Product             : ' + app_name +
  '\n  URL                 : ' + url      +
  '\n  Installed version   : ' + version  +
  '\n  End of support date : ' + eol_date +
  '\n  Latest version(s)   : ' + latest   +
  '\n' + note;
security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
