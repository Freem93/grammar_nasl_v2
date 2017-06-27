#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-101.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75245);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-7296");
  script_bugtraq_id(64636);
  script_osvdb_id(101586);

  script_name(english:"openSUSE Security Update : poppler (openSUSE-SU-2014:0185-1)");
  script_summary(english:"Check for the openSUSE-2014-101 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"poppler was updated to fix a security issue :

  - Fix a DoS due to a format string error (bnc#859427
    CVE-2013-7296)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-02/msg00005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=859427"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected poppler packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler34-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler43");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler43-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:poppler-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:poppler-qt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:poppler-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:poppler-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-Poppler-0_18");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/04");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"libpoppler-cpp0-0.22.1-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpoppler-cpp0-debuginfo-0.22.1-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpoppler-devel-0.22.1-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpoppler-glib-devel-0.22.1-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpoppler-glib8-0.22.1-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpoppler-glib8-debuginfo-0.22.1-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpoppler-qt4-4-0.22.1-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpoppler-qt4-4-debuginfo-0.22.1-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpoppler-qt4-devel-0.22.1-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpoppler34-0.22.1-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpoppler34-debuginfo-0.22.1-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"poppler-debugsource-0.22.1-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"poppler-qt-debugsource-0.22.1-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"poppler-tools-0.22.1-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"poppler-tools-debuginfo-0.22.1-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"typelib-1_0-Poppler-0_18-0.22.1-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpoppler-cpp0-0.24.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpoppler-cpp0-debuginfo-0.24.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpoppler-devel-0.24.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpoppler-glib-devel-0.24.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpoppler-glib8-0.24.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpoppler-glib8-debuginfo-0.24.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpoppler-qt4-4-0.24.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpoppler-qt4-4-debuginfo-0.24.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpoppler-qt4-devel-0.24.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpoppler43-0.24.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpoppler43-debuginfo-0.24.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"poppler-debugsource-0.24.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"poppler-qt-debugsource-0.24.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"poppler-tools-0.24.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"poppler-tools-debuginfo-0.24.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"typelib-1_0-Poppler-0_18-0.24.3-8.1") ) flag++;

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
