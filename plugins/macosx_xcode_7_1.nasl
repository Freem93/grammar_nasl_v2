#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86570);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:52:11 $");

  script_cve_id("CVE-2015-7030");
  script_osvdb_id(129326);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-10-21-7");

  script_name(english:"Apple Xcode < 7.1 (Mac OS X)");
  script_summary(english:"Checks the version of Xcode.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has an application installed that is affected
by a vulnerability due to unexpected type conversions.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Xcode installed on the remote Mac OS X host is
prior to 7.1. It is, therefore, affected by a vulnerability in
Swift-based programs due to unexpected values being returned for
certain type conversions. An unauthenticated, remote attacker can
exploit this, by manipulating return values, to circumvent controls in
program logic.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT205379");
  # http://prod.lists.apple.com/archives/security-announce/2015/Oct/msg00008.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea707e69");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Xcode version 7.1, which is available for OS X
version 10.10.5 (Yosemite) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/10/21");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/23");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:apple:xcode");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_xcode_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Apple Xcode");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item_or_exit("Host/MacOSX/Version");

# Patch is only available for OS X 10.10.5 and later
if (ereg(pattern:"Mac OS X 10\.([0-9]\.[0-9]|10\.[0-4]$)", string:os))
  audit(AUDIT_OS_NOT, "Mac OS X 10.10.5 or above");

appname = "Apple Xcode";

install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
path = install["path"];
ver = install["version"];

fix = '7.1';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(port:0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver, path);
