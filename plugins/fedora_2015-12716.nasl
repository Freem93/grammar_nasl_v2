#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-12716.
#

include("compat.inc");

if (description)
{
  script_id(85362);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/10/19 22:57:25 $");

  script_cve_id("CVE-2015-5704", "CVE-2015-5705");
  script_xref(name:"FEDORA", value:"2015-12716");

  script_name(english:"Fedora 21 : devscripts-2.15.8-1.fc21 (2015-12716)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to version 2.15.8, see
http://metadata.ftp-master.debian.org/changelogs//main/d/devscripts/de
vscripts_2.15.8_changelog for details. Fixes CVE-2015-5705. Update to
version 2.15.7, see
http://metadata.ftp-master.debian.org/changelogs//main/d/devscripts/de
vscripts_2.15.7_changelog for details. This update fixes licensecheck
refusing to parse some text files such as C++ source files. Update to
version 2.15.6, see
http://metadata.ftp-master.debian.org/changelogs//main/d/devscripts/de
vscripts_2.15.6_changelog for details. Update to version 2.15.6, see
http://metadata.ftp-master.debian.org/changelogs//main/d/devscripts/de
vscripts_2.15.6_changelog for details. This update fixes licensecheck
refusing to parse some text files such as C++ source files. Update to
version 2.15.6, see
http://metadata.ftp-master.debian.org/changelogs//main/d/devscripts/de
vscripts_2.15.6_changelog for details. Update to version 2.15.6, see
http://metadata.ftp-master.debian.org/changelogs//main/d/devscripts/de
vscripts_2.15.6_changelog for details. Update to version 2.15.7, see
http://metadata.ftp-master.debian.org/changelogs//main/d/devscripts/de
vscripts_2.15.7_changelog for details. This update fixes licensecheck
refusing to parse some text files such as C++ source files. Update to
version 2.15.6, see
http://metadata.ftp-master.debian.org/changelogs//main/d/devscripts/de
vscripts_2.15.6_changelog for details. Update to version 2.15.6, see
http://metadata.ftp-master.debian.org/changelogs//main/d/devscripts/de
vscripts_2.15.6_changelog for details. This update fixes licensecheck
refusing to parse some text files such as C++ source files. Update to
version 2.15.6, see
http://metadata.ftp-master.debian.org/changelogs//main/d/devscripts/de
vscripts_2.15.6_changelog for details. Update to version 2.15.6, see
http://metadata.ftp-master.debian.org/changelogs//main/d/devscripts/de
vscripts_2.15.6_changelog for details.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://metadata.ftp-master.debian.org/changelogs//main/d/devscripts/devscripts_2.15.6_changelog
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9a3c9b3b"
  );
  # http://metadata.ftp-master.debian.org/changelogs//main/d/devscripts/devscripts_2.15.7_changelog
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?37242079"
  );
  # http://metadata.ftp-master.debian.org/changelogs//main/d/devscripts/devscripts_2.15.8_changelog
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8dfde218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1249635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1249645"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-August/163710.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d9449377"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected devscripts package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:devscripts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:21");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^21([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 21.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC21", reference:"devscripts-2.15.8-1.fc21")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "devscripts");
}
