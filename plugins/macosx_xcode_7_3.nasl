#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90148);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/03/25 14:32:21 $");

  script_cve_id(
    "CVE-2015-3184",
    "CVE-2015-3187",
    "CVE-2016-1765"
  );
  script_bugtraq_id(
    76273,
    76274
  );
  script_osvdb_id(
    125798,
    125799,
    136152
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-03-21-4");

  script_name(english:"Apple Xcode < 7.3 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version of Xcode.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Xcode installed on the remote Mac OS X host is
prior to 7.3. It is, therefore, affected by multiple vulnerabilities :

  - A flaw exists in Apache Subversion in mod_authz_svn due
    to a failure to properly restrict anonymous access. An
    unauthenticated, remote attacker can exploit this, via a
    crafted path name, to read hidden files. (CVE-2015-3184)

  - A flaw exists in Apache Subversion in the
    svn_repos_trace_node_locations() function that causes
    the first readable path to be returned when it
    encounters an unreadable path when following a node's
    history. An authenticated, remote attacker can exploit
    this to access paths that were intended to be hidden.
    (CVE-2015-3187)

  - Multiple unspecified memory corruption issues exist in
    otool due to improper validation of user-supplied input.
    A local attacker can exploit these to cause a denial of
    service or to execute arbitrary code. (CVE-2016-1765)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-ca/HT206172");
  # http://prod.lists.apple.com/archives/security-announce/2016/Mar/msg00003.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5df80fa5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Xcode version 7.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/08/05");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/24");

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

fix = '7.3';

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
