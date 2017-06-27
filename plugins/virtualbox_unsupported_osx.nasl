#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92788);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/08/08 17:29:03 $");

  script_name(english:"Oracle VirtualBox Unsupported Version Detection (Mac OS X)");
  script_summary(english:"Checks the Oracle VirtualBox version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Mac OS X host is
no longer supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Oracle VirtualBox on the remote Mac OS X host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # http://www.oracle.com/technetwork/server-storage/virtualbox/support/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?925c7fb8");
  # http://www.oracle.com/us/support/library/lifetime-support-hardware-301321.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?466fb425");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Download_Old_Builds");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Oracle VirtualBox that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_virtualbox_installed.nbin");
  script_require_keys("installed_sw/VirtualBox");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

appname = 'VirtualBox';
install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
version = install['version'];
path = install['path'];

# versions < 5 are unsupported
if (version =~ "^[0-4]($|\.\d+)")
{
  register_unsupported_product(product_name:appname, version:version, cpe_base:"oracle:vm_virtualbox");

  report = '\n  Path              : ' + path +
           '\n  Installed version : ' + version +
           '\n  EOL URL           : https://www.virtualbox.org/wiki/Download_Old_Builds' +
           '\n  Solution          : Upgrade to a supported version of VirtualBox';

  port = get_service(svc:"ssh", default:22);

  security_report_v4(port:22, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, version);
