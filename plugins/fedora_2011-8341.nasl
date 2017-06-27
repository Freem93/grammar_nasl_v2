#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-8341.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(55496);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/11 13:32:16 $");

  script_cve_id("CVE-2011-1752", "CVE-2011-1783", "CVE-2011-1921");
  script_bugtraq_id(48091);
  script_osvdb_id(73245, 73246, 73247);
  script_xref(name:"FEDORA", value:"2011-8341");

  script_name(english:"Fedora 14 : subversion-1.6.17-1.fc14 (2011-8341)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update includes the latest release of Subversion, fixing three
security issues :

An infinite loop flaw was found in the way the mod_dav_svn module
processed certain data sets. If the SVNPathAuthz directive was set to
'short_circuit', and path-based access control for files and
directories was enabled, a malicious, remote user could use this flaw
to cause the httpd process serving the request to consume an excessive
amount of system memory. (CVE-2011-1783)

A NULL pointer dereference flaw was found in the way the mod_dav_svn
module processed requests submitted against the URL of a baselined
resource. A malicious, remote user could use this flaw to cause the
httpd process serving the request to crash. (CVE-2011-1752)

An information disclosure flaw was found in the way the mod_dav_svn
module processed certain URLs when path-based access control for files
and directories was enabled. A malicious, remote user could possibly
use this flaw to access certain files in a repository that would
otherwise not be accessible to them. Note: This vulnerability cannot
be triggered if the SVNPathAuthz directive is set to 'short_circuit'.
(CVE-2011-1921)

The Fedora Project would like to thank the Apache Subversion project
for reporting these issues. Upstream acknowledges Joe Schaefer of the
Apache Software Foundation as the original reporter of CVE-2011-1752;
Ivan Zhakov of VisualSVN as the original reporter of CVE-2011-1783;
and Kamesh Jayachandran of CollabNet, Inc. as the original reporter of
CVE-2011-1921.

The following bugs are also fixed in this release :

  - make 'blame -g' more efficient on with large mergeinfo

    - preserve log message with a non-zero editor exit

    - fix FSFS cache performance on 64-bit platforms

    - make svn cleanup tolerate obstructed directories

    - fix deadlock in multithreaded servers serving FSFS
      repositories

    - detect very occasional corruption and abort commit

    - fixed: file externals cause non-inheritable mergeinfo

    - fixed: file externals cause mixed-revision working
      copies

    - fixed: write-through proxy could direcly commit to
      slave

    - detect a particular corruption condition in FSFS

    - improve error message when clients refer to unkown
      revisions

    - bugfixes and optimizations to the DAV mirroring code

    - fixed: locked and deleted file causes tree conflict

    - fixed: update touches locked file with svn:keywords
      property

    - fix svnsync handling of directory copyfrom

    - fix 'log -g' excessive duplicate output

    - fix svnsync copyfrom handling bug with BDB

    - server-side validation of svn:mergeinfo syntax during
      commit

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=709952"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-July/062211.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b397d08e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^14([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 14.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC14", reference:"subversion-1.6.17-1.fc14")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "subversion");
}
