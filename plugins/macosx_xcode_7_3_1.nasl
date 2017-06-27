#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91262);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/20 14:12:05 $");

  script_cve_id(
    "CVE-2016-2315",
    "CVE-2016-2324"
  );
  script_osvdb_id(
    135893,
    135894
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-05-03-1");

  script_name(english:"Apple Xcode < 7.3.1 Multiple RCE (Mac OS X)");
  script_summary(english:"Checks the version of Xcode.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Xcode installed on the remote Mac OS X host is
prior to 7.3.1. It is, therefore, affected by multiple remote code
execution vulnerabilities in the bundled version of Git due to
overflow conditions in the path_name() function in revision.c that are
triggered when pushing or cloning a repository with a large filename
or containing a large number of nested trees. A remote attacker can
exploit these issues to cause a heap-based buffer overflow, resulting
in the execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT206338");
  # http://prod.lists.apple.com/archives/security-announce/2016/May/msg00000.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1dc5b9fd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Xcode version 7.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/05/04");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/19");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:apple:xcode");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

# Patch is only available for OS X 10.11 and later
if (ereg(pattern:"Mac OS X 10\.([0-9]|10)(\.|$)", string:os))
  audit(AUDIT_OS_NOT, "Mac OS X 10.11 or above");

appname = "Apple Xcode";

install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
path = install["path"];
ver = install["version"];

fix = '7.3.1';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
{
  report_items = make_array(
    "Path", path,
    "Installed version", ver,
    "Fixed version", fix
  );
  order = make_list("Path", "Installed version", "Fixed version");
  report = report_items_str(report_items:report_items, ordered_fields:order);
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver, path);
