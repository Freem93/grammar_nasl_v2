#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77863);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/16 14:02:53 $");

  script_cve_id("CVE-2014-0032");
  script_bugtraq_id(65434);
  script_osvdb_id(102927);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-09-17-7");

  script_name(english:"Apple Xcode < 6.0.1 (Mac OS X)");
  script_summary(english:"Checks the version of Xcode.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Apple Xcode prior to 6.0.1
installed. It is, therefore, affected by a denial of service
vulnerability in the bundled Subversion component. The 'get_resource'
function in 'repos.c' in the 'mod_dav_svn' module allows remote
attackers to cause a denial of service when the 'SVNListParentPath'
option is enabled.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6444");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/533477/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Xcode version 6.0.1 or later, which is available for
OS X 10.9.4 (Mavericks) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:xcode");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_xcode_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Apple Xcode");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

# Patch is only available for OS X 10.9.4 and later
if (!ereg(pattern:"Mac OS X 10\.9\.([4-9]|1[0-9])([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.9.4 or above.");

appname = "Apple Xcode";

install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
path = install["path"];
ver = install["version"];

fix = '6.0.1';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(port:0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver, path);
