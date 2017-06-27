#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@

include("compat.inc");

if (description)
{
  script_id(80828);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/03/11 18:32:16 $");

  script_cve_id("CVE-2014-9390");
  script_bugtraq_id(71732);
  script_osvdb_id(116041);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-12-18-1");

  script_name(english:"Apple Xcode < 6.2 beta 3 .git/config Command Execution (Mac OS X) (deprecated)");
  script_summary(english:"Checks the version of Xcode.");

  script_set_attribute(attribute:"synopsis", value:"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Apple Xcode prior to 6.2
beta 3. It is, therefore, affected by a remote command execution
vulnerability when processing git trees in a case-insensitive or
case-normalizing file system. A remote attacker, using a specially
crafted git tree, can overwrite a user's '.git/config' file when the
user clones or checks out a repository, allowing arbitrary command
execution.

This plugin has been deprecated. It detects Xcode installations
vulnerable to CVE-2014-9390, and was created before Apple released a
security update to fix this vulnerability. On March 9, 2015, a
security update for Xcode has been released. The update fixes
multiple vulnerabilities (including CVE-2014-9390). A separate plugin
(ID 81758) has been created to detect that update. That plugin should
be used instead of this one.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/en-us/HT204147");
  script_set_attribute(attribute:"see_also", value:"http://article.gmane.org/gmane.linux.kernel/1853266");
  # http://git-blame.blogspot.com/2014/12/git-1856-195-205-214-and-221-and.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?afc47628");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Malicious Git and Mercurial HTTP Server For CVE-2014-9390');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:xcode");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("macosx_xcode_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Apple Xcode");

  exit(0);
}

exit(0, 'This plugin has been deprecated. Use Nessus plugin ID 81758 instead.');

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_HOST_NOT, "running Mac OS X");
# Patch is only available for OS X 10.9.4 and later
if (ereg(pattern:"Mac OS X ([0-9]|10\.[0-8]|10\.9\.[0-3])([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.9.4 or above");

appname = "Apple Xcode";
appbeta = "Apple Xcode-Beta";

vuln = FALSE;

count = get_install_count(app_name:appname);
if (count != 0)
{
  installs = get_installs(app_name:appname);
  foreach install (installs[1])
  {
    path = install["path"];
    ver = install["version"];

    #6.1.1 is the current maximum Xcode affected
    #check to see if a vulnerable version of Xcode is installed
    if (ver_compare(ver:ver, fix:'6.1.1', strict:FALSE) <= 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + ver +
        '\n';
      vuln = TRUE;
    }
  }
}

count = get_install_count(app_name:appbeta);
if (count != 0)
{
  installs = get_installs(app_name:appbeta);
  foreach install (installs[1])
  {
    path = install["path"];
    ver = install["version"];

    if(ver_compare(ver:ver, fix:'6.2', strict:FALSE) < 0)
    {
      report +=
        '\n  Beta path              : ' + path +
        '\n  Installed Beta version : ' + ver +
        '\n';
      vuln = TRUE;
    }
  }
}

if (vuln)
{
  if (report_verbosity > 0)
    security_warning(port:0, extra:report);
  else security_warning(port:0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname+'(-Beta)');
