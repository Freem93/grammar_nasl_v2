#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97995);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/04/17 19:02:48 $");

  script_name(english:"IBM Domino Unsupported Version Detection");
  script_summary(english:"Checks the version of IBM Domino.");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of IBM Domino is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
IBM Domino (formerly IBM Lotus Domino) on the remote host is no longer
supported.

Lack of support implies that no new security patches for the product
will be released by the vendor under a standard support contract. As a
result, it is likely to contain security vulnerabilities.");
  # https://www-01.ibm.com/software/support/lifecycleapp/PLCDetail.wss?psynkey=A878922V64965A41&synkey=T980158S92317Y11&from=spf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9b5bd527");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of IBM Domino that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:domino");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("lotus_domino_installed.nasl", "domino_installed.nasl");
  script_require_ports("installed_sw/IBM Domino", "Domino/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

appname = 'IBM Domino';
version = NULL;
port    = 0;
supported_versions = '8.5.x / 9.0.x';

# Credentialed
if (get_install_count(app_name:appname))
{
  install = get_single_install(app_name:appname);
  version = install['version'];
  path    = install['path'];

  port = get_kb_item('SMB/transport');
  if (isnull(port)) port = 445;
}
# Uncredentialed
else
{
  version = get_kb_item("Domino/Version");
  port = get_kb_item("Domino/Version_provided_by_port");
  if (isnull(port)) port = 0;
}

if (isnull(version)) audit(AUDIT_NOT_INST, appname);

if (version =~ "^([0-7]|8\.0)([^0-9]|$)")
{
  register_unsupported_product(product_name:appname, version:version,
                               cpe_base:"cpe:/a:ibm:lotus_domino");
  report =
    '\n  Product            : ' + appname;
    if (!empty_or_null(path))
      report += '\n  Path               : ' + path;
  report +=
    '\n  Installed version  : ' + version +
    '\n  Supported versions : ' + supported_versions +
    '\n  EOL URL            : http://www.nessus.org/u?9b5bd527' +
    '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else
{
  if (!empty_or_null(path))
    audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
  else
    audit(AUDIT_LISTEN_NOT_VULN, appname, port, version); 
}
