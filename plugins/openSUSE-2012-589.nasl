#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-589.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74746);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2012-2736");

  script_name(english:"openSUSE Security Update : NetworkManager (openSUSE-SU-2012:1151-1)");
  script_summary(english:"Check for the openSUSE-2012-589 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The broken AdHoc WPA mode was disabled in NetworkManager, which would
have created an open network instead. (CVE-2012-2736)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-09/msg00049.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=767219"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected NetworkManager packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:NetworkManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:NetworkManager-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:NetworkManager-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:NetworkManager-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:NetworkManager-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:NetworkManager-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnm-glib-vpn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnm-glib-vpn1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnm-glib-vpn1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnm-glib-vpn1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnm-glib4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnm-glib4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnm-glib4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnm-glib4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnm-util2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnm-util2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnm-util2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnm-util2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/05");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"NetworkManager-0.9.1.90-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"NetworkManager-debuginfo-0.9.1.90-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"NetworkManager-debugsource-0.9.1.90-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"NetworkManager-devel-0.9.1.90-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"NetworkManager-lang-0.9.1.90-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libnm-glib-vpn1-0.9.1.90-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libnm-glib-vpn1-debuginfo-0.9.1.90-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libnm-glib4-0.9.1.90-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libnm-glib4-debuginfo-0.9.1.90-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libnm-util2-0.9.1.90-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libnm-util2-debuginfo-0.9.1.90-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"NetworkManager-devel-32bit-0.9.1.90-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libnm-glib-vpn1-32bit-0.9.1.90-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libnm-glib-vpn1-debuginfo-32bit-0.9.1.90-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libnm-glib4-32bit-0.9.1.90-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libnm-glib4-debuginfo-32bit-0.9.1.90-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libnm-util2-32bit-0.9.1.90-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libnm-util2-debuginfo-32bit-0.9.1.90-4.11.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "NetworkManager");
}
