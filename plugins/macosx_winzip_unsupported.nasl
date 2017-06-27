#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78674);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/03/04 22:33:14 $");

  script_name(english:"WinZip Unsupported (Mac OS X)");
  script_summary(english:"Checks the version of WinZip.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is no longer supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
WinZip on the remote Mac OS X host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.winzip.com");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of WinZip that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:winzip:winzip");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_winzip_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/WinZip");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("install_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("Host/local_checks_enabled");
get_kb_item_or_exit("Host/MacOSX/Version");

appname = 'WinZip';

install = get_single_install(app_name:appname);
path = install['path'];
version = install['version'];

currently_supported = "2.x - 4.x";
currently_unsupported_cutoff = "2.0.0";

if (ver_compare(ver:version, fix:currently_unsupported_cutoff, strict:FALSE) < 0)
{
  register_unsupported_product(product_name:appname,
                               cpe_base:"winzip:winzip", version:version);

  report =
    '\n  Path               : ' + path +
    '\n  Installed version  : ' + version +
    '\n  Supported versions : ' + currently_supported +
    '\n  EOL URL            : http://kb.winzip.com/kb/entry/132/' +
    '\n';
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_NOT_INST, "An unsupported version of "+appname);
