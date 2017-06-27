#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-539.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74730);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2012-2944");
  script_osvdb_id(82409);

  script_name(english:"openSUSE Security Update : nut (openSUSE-SU-2012:1069-1)");
  script_summary(english:"Check for the openSUSE-2012-539 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The nut upsd is prone to multiple flaws that allow remote attackers to
cause a denial of service (application crash) by sending unexpected
data."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-08/msg00049.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=764699"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected nut packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libupsclient1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libupsclient1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nut-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nut-cgi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nut-classic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nut-classic-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nut-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nut-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nut-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nut-drivers-net");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nut-drivers-net-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nut-hal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nut-hal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/25");
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

if ( rpm_check(release:"SUSE11.4", reference:"libupsclient1-2.6.0-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libupsclient1-debuginfo-2.6.0-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"nut-2.6.0-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"nut-cgi-2.6.0-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"nut-cgi-debuginfo-2.6.0-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"nut-classic-2.6.0-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"nut-classic-debuginfo-2.6.0-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"nut-debuginfo-2.6.0-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"nut-debugsource-2.6.0-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"nut-devel-2.6.0-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"nut-drivers-net-2.6.0-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"nut-drivers-net-debuginfo-2.6.0-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"nut-hal-2.6.0-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"nut-hal-debuginfo-2.6.0-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libupsclient1-2.6.1-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libupsclient1-debuginfo-2.6.1-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"nut-2.6.1-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"nut-cgi-2.6.1-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"nut-cgi-debuginfo-2.6.1-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"nut-debuginfo-2.6.1-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"nut-debugsource-2.6.1-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"nut-devel-2.6.1-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"nut-drivers-net-2.6.1-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"nut-drivers-net-debuginfo-2.6.1-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libupsclient1-2.6.3-2.4.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libupsclient1-debuginfo-2.6.3-2.4.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nut-2.6.3-2.4.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nut-cgi-2.6.3-2.4.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nut-cgi-debuginfo-2.6.3-2.4.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nut-debuginfo-2.6.3-2.4.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nut-debugsource-2.6.3-2.4.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nut-devel-2.6.3-2.4.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nut-drivers-net-2.6.3-2.4.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nut-drivers-net-debuginfo-2.6.3-2.4.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nut");
}
