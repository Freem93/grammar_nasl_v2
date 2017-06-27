#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76333);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/09/24 21:08:39 $");

  script_name(english:"F5 Networks ARX Data Manager Unsupported Version Detection");
  script_summary(english:"Performs a version check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of a file management
platform.");
  script_set_attribute(attribute:"description", value:
"The remote host is running F5 Networks ARX Data Manager. According to
the vendor, this product is no longer supported and security fixes
will not be released. As a result, it is likely to contain security
vulnerabilities.");
  # http://support.f5.com/kb/en-us/solutions/public/14000/700/sol14791.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67ee3a80");
  script_set_attribute(attribute:"solution", value:"Contact the vendor or migrate to a different product.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:arx_data_manager");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("f5_data_manager_detect.nbin");
  script_require_keys("installed_sw/F5 Networks ARX Data Manager");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = "F5 Networks ARX Data Manager";

get_kb_item_or_exit(ROOT_KB_KEY + app_name);
port = get_http_port(default:443);

installs = get_installs(app_name:app_name, port:port);
if (installs[0] == IF_NOT_FOUND) audit(AUDIT_WEB_APP_NOT_INST, app_name, port);

report = '';
foreach install (installs[1])
{
  register_unsupported_product(product_name:app_name,
                               version:install['version'], cpe_base:"f5:arx_data_manager");

  report += '\n  URL : ' + build_url(qs:install['path'], port:port);
}
report += '\n';


if (report_verbosity > 0) security_hole(extra:report, port:port);
else security_hole(port);
