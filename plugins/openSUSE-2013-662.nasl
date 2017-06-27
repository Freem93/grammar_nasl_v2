#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-662.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75126);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2012-2142");
  script_osvdb_id(96254);

  script_name(english:"openSUSE Security Update : poppler (openSUSE-SU-2013:1371-1)");
  script_summary(english:"Check for the openSUSE-2013-662 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"poppler was updated to fix a security problem. PDF files could emit
messages with terminal escape sequences which could be used to inject
shell code if the user ran a PDF viewer from a terminal shell
(CVE-2012-2142).

Also a bug was fixed to avoid division by zero when using
origpagesizes option (bnc#795582)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-08/msg00049.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=795582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=834476"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected poppler packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-cpp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-cpp0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-glib8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-glib8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-qt4-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-qt4-4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-qt4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler25");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler25-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:poppler-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:poppler-qt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:poppler-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:poppler-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-Poppler-0_18");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/14");
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
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"libpoppler-cpp0-0.20.0-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpoppler-cpp0-debuginfo-0.20.0-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpoppler-devel-0.20.0-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpoppler-glib-devel-0.20.0-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpoppler-glib8-0.20.0-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpoppler-glib8-debuginfo-0.20.0-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpoppler-qt4-4-0.20.0-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpoppler-qt4-4-debuginfo-0.20.0-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpoppler-qt4-devel-0.20.0-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpoppler25-0.20.0-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpoppler25-debuginfo-0.20.0-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"poppler-debugsource-0.20.0-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"poppler-qt-debugsource-0.20.0-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"poppler-tools-0.20.0-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"poppler-tools-debuginfo-0.20.0-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"typelib-1_0-Poppler-0_18-0.20.0-2.13.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "poppler");
}
