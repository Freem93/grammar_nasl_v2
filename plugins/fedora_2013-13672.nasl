#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-13672.
#

include("compat.inc");

if (description)
{
  script_id(69355);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/19 21:12:41 $");

  script_cve_id("CVE-2013-1968", "CVE-2013-2088", "CVE-2013-2112", "CVE-2013-4131");
  script_xref(name:"FEDORA", value:"2013-13672");

  script_name(english:"Fedora 18 : subversion-1.7.11-1.fc18.1 (2013-13672)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update includes the latest release of Apache Subversion 1.7,
version 1.7.11. Several security vulnerabilities are fixed in this
update :

Subversion's mod_dav_svn Apache HTTPD server module will trigger an
assertion on some requests made against a revision root. This can lead
to a DoS. If assertions are disabled it will trigger a read overflow
which may cause a segmentation fault or undefined behavior. Commit
access is required to exploit this. (CVE-2013-4131)

If a filename which contains a newline character (ASCII 0x0a) is
committed to a repository using the FSFS format, the resulting
revision is corrupt. This can lead to disruption for users of the
repository. (CVE-2013-1968)

Subversion's contrib/ directory contains two example hook scripts,
which use 'svnlook changed' to examine a revision or transaction and
then pass those paths as arguments to further 'svnlook' commands,
without properly escaping the command-line. (CVE-2013-2088)

Subversion's svnserve server process may exit when an incoming TCP
connection is closed early in the connection process. This can lead to
disruption for users of the server. (CVE-2013-2112)

The following client-side bugs were fixed in the 1.7.10 release :

  - fix 'svn revert' 'no such table: revert_list' spurious
    error

    - fix 'svn diff' doesn't show some locally added files

    - fix changelist filtering when --changelist values
      aren't UTF8

    - fix 'svn diff --git' shows wrong copyfrom

    - fix 'svn diff -x-w' shows wrong changes

    - fix 'svn blame' sometimes shows every line as modified

    - fix regression in 'svn status -u' output for externals

    - fix file permissions change on commit of file with
      keywords

    - improve some fatal error messages

    - fix externals not removed when working copy is made
      shallow

The following server-side bugs are fixed :

  - fix repository corruption due to newline in filename

    - fix svnserve exiting when a client connection is
      aborted

    - fix svnserve memory use after clear

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=970014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=970027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=970037"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=986194"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-August/113943.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb0cfdf6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^18([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 18.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC18", reference:"subversion-1.7.11-1.fc18.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "subversion");
}
