#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77279);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_name(english:"Tenable Log Correlation Engine Unix / Linux Clients Unsupported Version Detection");
  script_summary(english:"Checks the LCE *nix Client version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of the Tenable Log
Correlation Engine Client.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of the Tenable Log
Correlation Engine (LCE) Unix / Linux Client on the remote host is no
longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of the Log Correlation Engine Unix / Linux Client
that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"see_also", value:"http://www.tenable.com/products/log-correlation-engine");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:tenable:log_correlation_engine_client");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:tenable:log_correlation_engine_client:unix");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:tenable:log_correlation_engine_client:linux");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:tenable:log_correlation_engine_client:netflow");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:tenable:log_correlation_engine_client:network");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:tenable:log_correlation_engine_client:wmi");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:tenable:log_correlation_engine_client:splunk");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:tenable:log_correlation_engine_client:opsec");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:tenable:log_correlation_engine_client:rdep");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:tenable:log_correlation_engine_client:sdee");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("lce_client_installed_unix.nbin");
  script_require_ports(
    "installed_sw/Log Correlation Engine Nix Client",
    "installed_sw/Log Correlation Engine NetFlow Monitor",
    "installed_sw/Log Correlation Engine Network Monitor",
    "installed_sw/Log Correlation Engine OPSEC Client",
    "installed_sw/Log Correlation Engine RDEP Monitor",
    "installed_sw/Log Correlation Engine SDEE Monitor",
    "installed_sw/Log Correlation Engine Splunk Client",
    "installed_sw/Log Correlation Engine WMI Monitor"
  );

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

# Regex is for versions we do not support.
package_info['Log Correlation Engine Nix Client']['Regex'] = "^[0-3]\.";
package_info['Log Correlation Engine Nix Client']['Supported'] = '4.0.x / 4.2.x';
package_info['Log Correlation Engine Nix Client']['XML'] = 'nix:';
package_info['Log Correlation Engine NetFlow Monitor']['Regex'] = "^[0-3]\.";
package_info['Log Correlation Engine NetFlow Monitor']['Supported'] = '4.0.x / 4.2.x';
package_info['Log Correlation Engine NetFlow Monitor']['XML'] = 'netflow:';
package_info['Log Correlation Engine Network Monitor']['Regex'] = "^[0-3]\.";
package_info['Log Correlation Engine Network Monitor']['Supported'] = '4.0.x / 4.2.x';
package_info['Log Correlation Engine Network Monitor']['XML'] = 'network:';
package_info['Log Correlation Engine OPSEC Client']['Regex'] = "^[0-2]|3\.[0-5]\.";
package_info['Log Correlation Engine OPSEC Client']['Supported'] = '3.6.x';
package_info['Log Correlation Engine OPSEC Client']['XML'] = 'opsec:';
package_info['Log Correlation Engine RDEP Monitor']['Regex'] = "^[0-2]|3\.[0-5]\.";
package_info['Log Correlation Engine RDEP Monitor']['Supported'] = '3.6.x';
package_info['Log Correlation Engine RDEP Monitor']['XML'] = 'rdep:';
package_info['Log Correlation Engine SDEE Monitor']['Regex'] = "^[0-2]\.|3\.[0-5]\.|4\.[01]\.";
package_info['Log Correlation Engine SDEE Monitor']['Supported'] = '3.6.x / 4.2.x';
package_info['Log Correlation Engine SDEE Monitor']['XML'] = 'sdee:';
package_info['Log Correlation Engine Splunk Client']['Regex'] = "^[0-2]\.|3\.[0-5]\.|4\.[01]\.";
package_info['Log Correlation Engine Splunk Client']['Supported'] = '3.6.x / 4.2.x';
package_info['Log Correlation Engine Splunk Client']['XML'] = 'splunk:';
package_info['Log Correlation Engine WMI Monitor']['Regex'] = "^[0-3]\.";
package_info['Log Correlation Engine WMI Monitor']['Supported'] = '4.0.x / 4.2.x';
package_info['Log Correlation Engine WMI Monitor']['XML'] = 'wmi:';

clients = make_list('Log Correlation Engine Nix Client', 'Log Correlation Engine NetFlow Monitor',
    'Log Correlation Engine Network Monitor', 'Log Correlation Engine OPSEC Client',
    'Log Correlation Engine RDEP Monitor', 'Log Correlation Engine SDEE Monitor',
    'Log Correlation Engine Splunk Client', 'Log Correlation Engine WMI Monitor');

client = branch(clients);

get_install_count(app_name:client, exit_if_zero:TRUE);

regex = package_info[client]['Regex'];
supported = package_info[client]['Supported'];
xml = package_info[client]['XML'];

install = get_single_install(app_name:client, exit_if_unknown_ver:TRUE);
version = install['version'];

if (version =~ regex)
{
  register_unsupported_product(product_name:'Tenable Log Correlation Engine Client', is_custom_cpe:TRUE,
                               version:version, cpe_base:"tenable:log_correlation_engine:client:"+(xml - ":"));

  if (report_verbosity > 0)
  {
    report =
      '\n  Client             : ' + client +
      '\n  Installed version  : ' + version +
      '\n  Supported versions : ' + supported +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, client, version, install['path']);
