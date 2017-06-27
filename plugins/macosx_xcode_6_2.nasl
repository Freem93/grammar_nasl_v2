#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81758);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/13 20:14:28 $");

  script_cve_id(
    "CVE-2014-3522",
    "CVE-2014-3528",
    "CVE-2014-3580",
    "CVE-2014-8108",
    "CVE-2014-9390"
  );
  script_bugtraq_id(
    68995,
    69237,
    71725,
    71726,
    71732
  );
  script_osvdb_id(
    109748,
    109996,
    115921,
    115922,
    116041
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-03-09-4");

  script_name(english:"Apple Xcode < 6.2 (Mac OS X)");
  script_summary(english:"Checks the version of Xcode.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Apple Xcode installed on the remote Mac OS X host is prior to
version 6.2. It is, therefore, affected by the following
vulnerabilities :

  - Numerous errors exist related to the bundled version of
    Apache Subversion. (CVE-2014-3522, CVE-2014-3528,
    CVE-2014-3580, CVE-2014-8108)

  - An error exists related to the bundled version of Git
    that allows arbitrary files to be added to the .git
    folder. (CVE-2014-9390)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT204427");
  #http://lists.apple.com/archives/security-announce/2015/Mar/msg00003.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d35c04b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Xcode version 6.2 or later, which is available for OS
X 10.9.4 (Mavericks) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Malicious Git and Mercurial HTTP Server For CVE-2014-9390');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:xcode");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

# Patch is only available for OS X 10.9.4 and later
if (ereg(pattern:"Mac OS X 10\.([0-8]\.[0-9]$|9\.[0-3]$)", string:os))
  audit(AUDIT_OS_NOT, "Mac OS X 10.9.4 or above");

appname = "Apple Xcode";

install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
path = install["path"];
ver = install["version"];

fix = '6.2';

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
