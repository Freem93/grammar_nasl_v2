#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71457);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/03/22 19:26:12 $");

  script_name(english:"Tenable Log Correlation Engine Server Unsupported Version Detection");
  script_summary(english:"Checks the LCE Server version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of the Tenable Log
Correlation Engine Server.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Tenable Log Correlation
Engine (LCE) Server on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Log Correlation Engine Server that is
currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"see_also", value:"http://www.tenable.com/products/log-correlation-engine");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:log_correlation_engine");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("lce_installed.nbin");
  script_require_keys("installed_sw/Log Correlation Engine Server");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'Log Correlation Engine Server';

get_install_count(app_name:app, exit_if_zero:TRUE);

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
version = install['version'];

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] < 4)
{
  register_unsupported_product(product_name:'Tenable Log Correlation Engine Client', is_custom_cpe:FALSE,
                               version:version, cpe_base:"tenable:log_correlation_engine");

  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version  : ' + version +
      '\n  Supported versions : 4.0.x / 4.2.x / 4.4.x \n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, install['path']);
