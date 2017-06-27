#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-757.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74802);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2012-3500");
  script_osvdb_id(85613);

  script_name(english:"openSUSE Security Update : deb / update-alternatives (openSUSE-SU-2012:1437-1)");
  script_summary(english:"Check for the openSUSE-2012-757 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fix tmp issues in annotate-output (bnc#778291,
    CVE-2012-3500)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-11/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=778291"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected deb / update-alternatives packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:deb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:deb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:deb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:deb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:deb-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:update-alternatives");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:update-alternatives-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:update-alternatives-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.4|SUSE12\.1|SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4 / 12.1 / 12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"deb-1.15.6.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"deb-debuginfo-1.15.6.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"deb-debugsource-1.15.6.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"deb-devel-1.15.6.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"deb-lang-1.15.6.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"deb-1.15.8.10-9.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"deb-debuginfo-1.15.8.10-9.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"deb-debugsource-1.15.8.10-9.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"deb-devel-1.15.8.10-9.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"deb-lang-1.15.8.10-9.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"update-alternatives-1.15.8.10-9.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"update-alternatives-debuginfo-1.15.8.10-9.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"update-alternatives-debugsource-1.15.8.10-9.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"deb-1.16.3-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"deb-debuginfo-1.16.3-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"deb-debugsource-1.16.3-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"deb-devel-1.16.3-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"deb-lang-1.16.3-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"update-alternatives-1.16.3-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"update-alternatives-debuginfo-1.16.3-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"update-alternatives-debugsource-1.16.3-3.6.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "deb / deb-debuginfo / deb-debugsource / deb-devel / deb-lang / etc");
}
