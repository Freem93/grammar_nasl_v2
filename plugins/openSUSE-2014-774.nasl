#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-774.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(80047);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/12/16 15:17:31 $");

  script_cve_id("CVE-2014-9092");

  script_name(english:"openSUSE Security Update : libjpeg-turbo / libjpeg62-turbo (openSUSE-SU-2014:1637-1)");
  script_summary(english:"Check for the openSUSE-2014-774 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This libjpeg update fixes several security and non security issues :

  - bnc#906761: Passing special crafted jpeg file smashes
    stack (CVE-2014-9092)

  - bnc#771791: Fixed heap overflow"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-12/msg00055.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=771791"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=807183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=906761"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libjpeg-turbo / libjpeg62-turbo packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg-turbo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg-turbo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg-turbo-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg62");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg62-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg62-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg62-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg62-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg62-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg62-turbo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg62-turbo-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg8-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg8-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg8-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg8-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libturbojpeg0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libturbojpeg0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libturbojpeg0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libturbojpeg0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/16");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"libjpeg-turbo-1.2.1-19.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libjpeg-turbo-debuginfo-1.2.1-19.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libjpeg-turbo-debugsource-1.2.1-19.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libjpeg62-62.0.0-19.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libjpeg62-debuginfo-62.0.0-19.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libjpeg62-devel-62.0.0-19.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libjpeg62-turbo-1.2.1-19.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libjpeg62-turbo-debugsource-1.2.1-19.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libjpeg8-8.0.2-19.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libjpeg8-debuginfo-8.0.2-19.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libjpeg8-devel-8.0.2-19.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libjpeg62-32bit-62.0.0-19.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libjpeg62-debuginfo-32bit-62.0.0-19.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libjpeg62-devel-32bit-62.0.0-19.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libjpeg8-32bit-8.0.2-19.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libjpeg8-debuginfo-32bit-8.0.2-19.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libjpeg8-devel-32bit-8.0.2-19.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libjpeg-turbo-1.2.1-24.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libjpeg-turbo-debuginfo-1.2.1-24.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libjpeg-turbo-debugsource-1.2.1-24.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libjpeg62-62.0.0-24.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libjpeg62-debuginfo-62.0.0-24.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libjpeg62-devel-62.0.0-24.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libjpeg62-turbo-1.2.1-24.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libjpeg62-turbo-debugsource-1.2.1-24.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libjpeg8-8.0.2-24.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libjpeg8-debuginfo-8.0.2-24.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libjpeg8-devel-8.0.2-24.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libjpeg62-32bit-62.0.0-24.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libjpeg62-debuginfo-32bit-62.0.0-24.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libjpeg62-devel-32bit-62.0.0-24.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libjpeg8-32bit-8.0.2-24.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libjpeg8-debuginfo-32bit-8.0.2-24.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libjpeg8-devel-32bit-8.0.2-24.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libjpeg-turbo-1.3.1-30.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libjpeg-turbo-debuginfo-1.3.1-30.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libjpeg-turbo-debugsource-1.3.1-30.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libjpeg62-62.1.0-30.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libjpeg62-debuginfo-62.1.0-30.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libjpeg62-devel-62.1.0-30.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libjpeg62-turbo-1.3.1-30.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libjpeg62-turbo-debugsource-1.3.1-30.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libjpeg8-8.0.2-30.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libjpeg8-debuginfo-8.0.2-30.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libjpeg8-devel-8.0.2-30.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libturbojpeg0-8.0.2-30.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libturbojpeg0-debuginfo-8.0.2-30.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libjpeg62-32bit-62.1.0-30.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libjpeg62-debuginfo-32bit-62.1.0-30.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libjpeg62-devel-32bit-62.1.0-30.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libjpeg8-32bit-8.0.2-30.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libjpeg8-debuginfo-32bit-8.0.2-30.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libjpeg8-devel-32bit-8.0.2-30.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libturbojpeg0-32bit-8.0.2-30.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libturbojpeg0-debuginfo-32bit-8.0.2-30.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libjpeg-turbo / libjpeg-turbo-debuginfo / libjpeg-turbo-debugsource / etc");
}
