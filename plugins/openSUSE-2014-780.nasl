#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-780.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(80052);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/12/17 15:40:23 $");

  script_name(english:"openSUSE Security Update : firebird (openSUSE-SU-2014:1642-1)");
  script_summary(english:"Check for the openSUSE-2014-780 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:"Firebird server crashes when handling a malformed network packet."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-12/msg00060.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908127"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firebird packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:firebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:firebird-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:firebird-classic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:firebird-classic-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:firebird-classic-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:firebird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:firebird-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:firebird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:firebird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:firebird-superserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:firebird-superserver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfbclient2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfbclient2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfbclient2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfbclient2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfbclient2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfbembed-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfbembed2_5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfbembed2_5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/05");
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

if ( rpm_check(release:"SUSE12.3", reference:"firebird-2.5.2.26539-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"firebird-classic-2.5.2.26539-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"firebird-classic-debuginfo-2.5.2.26539-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"firebird-classic-debugsource-2.5.2.26539-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"firebird-debuginfo-2.5.2.26539-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"firebird-debugsource-2.5.2.26539-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"firebird-devel-2.5.2.26539-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"firebird-superserver-2.5.2.26539-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"firebird-superserver-debuginfo-2.5.2.26539-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libfbclient2-2.5.2.26539-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libfbclient2-debuginfo-2.5.2.26539-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libfbclient2-devel-2.5.2.26539-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libfbembed-devel-2.5.2.26539-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libfbembed2_5-2.5.2.26539-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libfbembed2_5-debuginfo-2.5.2.26539-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"firebird-32bit-2.5.2.26539-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"firebird-debuginfo-32bit-2.5.2.26539-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libfbclient2-32bit-2.5.2.26539-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libfbclient2-debuginfo-32bit-2.5.2.26539-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"firebird-2.5.2.26539-8.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"firebird-classic-2.5.2.26539-8.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"firebird-classic-debuginfo-2.5.2.26539-8.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"firebird-classic-debugsource-2.5.2.26539-8.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"firebird-debuginfo-2.5.2.26539-8.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"firebird-debugsource-2.5.2.26539-8.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"firebird-devel-2.5.2.26539-8.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"firebird-superserver-2.5.2.26539-8.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"firebird-superserver-debuginfo-2.5.2.26539-8.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libfbclient2-2.5.2.26539-8.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libfbclient2-debuginfo-2.5.2.26539-8.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libfbclient2-devel-2.5.2.26539-8.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libfbembed-devel-2.5.2.26539-8.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libfbembed2_5-2.5.2.26539-8.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libfbembed2_5-debuginfo-2.5.2.26539-8.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"firebird-32bit-2.5.2.26539-8.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"firebird-debuginfo-32bit-2.5.2.26539-8.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libfbclient2-32bit-2.5.2.26539-8.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libfbclient2-debuginfo-32bit-2.5.2.26539-8.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"firebird-2.5.2.26539-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"firebird-classic-2.5.2.26539-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"firebird-classic-debuginfo-2.5.2.26539-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"firebird-classic-debugsource-2.5.2.26539-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"firebird-debuginfo-2.5.2.26539-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"firebird-debugsource-2.5.2.26539-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"firebird-devel-2.5.2.26539-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"firebird-superserver-2.5.2.26539-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"firebird-superserver-debuginfo-2.5.2.26539-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libfbclient2-2.5.2.26539-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libfbclient2-debuginfo-2.5.2.26539-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libfbclient2-devel-2.5.2.26539-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libfbembed-devel-2.5.2.26539-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libfbembed2_5-2.5.2.26539-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libfbembed2_5-debuginfo-2.5.2.26539-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"firebird-32bit-2.5.2.26539-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"firebird-debuginfo-32bit-2.5.2.26539-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libfbclient2-32bit-2.5.2.26539-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libfbclient2-debuginfo-32bit-2.5.2.26539-14.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firebird-classic / firebird-classic-debuginfo / etc");
}
