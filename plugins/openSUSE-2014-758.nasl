#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-758.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(79820);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/05 13:44:22 $");

  script_cve_id("CVE-2014-8080", "CVE-2014-8090");

  script_name(english:"openSUSE Security Update : ruby19 (openSUSE-SU-2014:1589-1)");
  script_summary(english:"Check for the openSUSE-2014-758 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ruby19 was updated to fix two security issues.

These security issues were fixed :

  - Denial Of Service XML Expansion (CVE-2014-8080).

  - Denial Of Service XML Expansion (CVE-2014-8090).

Note: These are two separate issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-12/msg00035.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=902851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=905326"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ruby19 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby19-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby19-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby19-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby19-devel-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby19-doc-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby19-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby19-tk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"ruby19-1.9.3.p392-1.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-debuginfo-1.9.3.p392-1.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-debugsource-1.9.3.p392-1.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-devel-1.9.3.p392-1.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-devel-extra-1.9.3.p392-1.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-doc-ri-1.9.3.p392-1.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-tk-1.9.3.p392-1.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ruby19-tk-debuginfo-1.9.3.p392-1.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ruby19-1.9.3.p448-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ruby19-debuginfo-1.9.3.p448-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ruby19-debugsource-1.9.3.p448-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ruby19-devel-1.9.3.p448-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ruby19-devel-extra-1.9.3.p448-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ruby19-doc-ri-1.9.3.p448-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ruby19-tk-1.9.3.p448-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ruby19-tk-debuginfo-1.9.3.p448-2.8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby19 / ruby19-debuginfo / ruby19-debugsource / ruby19-devel / etc");
}
