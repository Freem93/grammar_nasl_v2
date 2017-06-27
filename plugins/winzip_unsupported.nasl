#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78675);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/26 17:44:28 $");

  script_name(english:"WinZip Unsupported Version Detection");
  script_summary(english:"Checks the version of WinZip.");

  script_set_attribute(attribute:"synopsis", value:
"A file compression and decompression application installed on the
remote host is no longer supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
WinZip on the remote Windows host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.winzip.com");
  script_set_attribute(attribute:"see_also", value:"http://kb.winzip.com/kb/entry/132/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of WinZip that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:winzip:winzip");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("winzip_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/WinZip");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("install_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

appname = 'WinZip';

install = get_single_install(app_name:appname);
path = install['path'];
disp_ver = install['display_version'];

ver = eregmatch(string:disp_ver, pattern:"^([0-9.]+)[^0-9.].*");
if(empty_or_null(ver)) audit(AUDIT_UNKNOWN_APP_VER, appname);
else ver = ver[1];

currently_supported = "18.x - 21.x";
currently_unsupported_cutoff = "18.0";

if (ver_compare(ver:ver, fix:currently_unsupported_cutoff, strict:FALSE) < 0)
{
  register_unsupported_product(product_name:"WinZip",
                               cpe_base:"winzip:winzip", version:disp_ver);

  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  report =
    '\n  Path               : ' + path +
    '\n  Installed version  : ' + disp_ver +
    '\n  Supported versions : ' + currently_supported +
    '\n  EOL URL            : http://kb.winzip.com/kb/entry/132/' +
    '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver, path);
