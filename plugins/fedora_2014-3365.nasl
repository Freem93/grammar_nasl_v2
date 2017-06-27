#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-3365.
#

include("compat.inc");

if (description)
{
  script_id(73033);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/19 22:32:17 $");

  script_cve_id("CVE-2014-0032");
  script_xref(name:"FEDORA", value:"2014-3365");

  script_name(english:"Fedora 20 : subversion-1.8.8-1.fc20 (2014-3365)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update includes the latest stable release of Subversion, fixing a
security issue (CVE-2014-0032) :

Subversion's mod_dav_svn Apache HTTPD server module will crash when it
receives an OPTIONS request against the server root and Subversion is
configured to handle the server root and SVNListParentPath is on.

This can lead to a DoS. There are no known instances of this problem
being exploited in the wild, but the details of how to exploit it have
been disclosed on the Subversion development mailing list.

For more information, see :

https://subversion.apache.org/security/CVE-2014-0032-advisory.txt

A number of client-side bug fixes are included in this update :

  - fix automatic relocate for wcs not at repository root

    - wc: improve performance when used with SQLite 3.8

    - copy: fix some scenarios that broke the working copy

    - move: fix errors when moving files between an external
      and the parent working copy

    - log: resolve performance regression in certain
      scenarios

    - merge: decrease work to detect differences between 3
      files

    - commit: don't change file permissions inappropriately

    - commit: fix assertion due to invalid pool lifetime

    - version: don't cut off the distribution version on
      Linux

    - flush stdout before exiting to avoid information being
      lost

    - status: fix missing sentinel value on warning codes

    - update/switch: improve some WC db queries that may
      return incorrect results depending on how SQLite is
      built

Server-side bugfixes :

  - reduce memory usage during checkout and export

    - fsfs: create rep-cache.db with proper permissions

    - mod_dav_svn: prevent crashes with SVNListParentPath on
      (CVE-2014-0032)

    - mod_dav_svn: fix SVNAllowBulkUpdates directive merging

    - mod_dav_svn: include requested property changes in
      reports

    - svnserve: correct default cache size in help text

    - svnadmin dump: reduce size of dump files with
      '--deltas'

    - resolve integer underflow that resulted in infinite
      loops

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1062042"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-March/130143.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b9d1bef2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://subversion.apache.org/security/CVE-2014-0032-advisory.txt"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^20([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 20.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC20", reference:"subversion-1.8.8-1.fc20")) flag++;


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
