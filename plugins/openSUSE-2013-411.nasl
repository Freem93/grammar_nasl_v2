#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-411.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74992);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:13 $");

  script_cve_id("CVE-2013-1940");

  script_name(english:"openSUSE Security Update : xorg-x11-server (openSUSE-SU-2013:0937-1)");
  script_summary(english:"Check for the openSUSE-2013-411 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"-
    U_xf86-fix-flush-input-to-work-with-Linux-evdev-device.p
    atch

  - So when we VT switch back and attempt to flush the input
    devices, we don't succeed because evdev won't return
    part of an event, since we were only asking for 4 bytes,
    we'd only get -EINVAL back. This could later cause
    events to be flushed that we shouldn't have gotten. This
    is a fix for CVE-2013-1940. (bnc#814653)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-05/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-06/msg00073.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=814653"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xorg-x11-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-Xvnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-Xvnc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-sdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/30");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"xorg-x11-Xvnc-7.6_1.10.4-36.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xorg-x11-Xvnc-debuginfo-7.6_1.10.4-36.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xorg-x11-server-7.6_1.10.4-36.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xorg-x11-server-debuginfo-7.6_1.10.4-36.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xorg-x11-server-debugsource-7.6_1.10.4-36.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xorg-x11-server-extra-7.6_1.10.4-36.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xorg-x11-server-extra-debuginfo-7.6_1.10.4-36.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xorg-x11-server-sdk-7.6_1.10.4-36.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xorg-x11-Xvnc-7.6_1.12.3-1.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xorg-x11-Xvnc-debuginfo-7.6_1.12.3-1.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xorg-x11-server-7.6_1.12.3-1.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xorg-x11-server-debuginfo-7.6_1.12.3-1.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xorg-x11-server-debugsource-7.6_1.12.3-1.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xorg-x11-server-extra-7.6_1.12.3-1.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xorg-x11-server-extra-debuginfo-7.6_1.12.3-1.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xorg-x11-server-sdk-7.6_1.12.3-1.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xorg-x11-server-7.6_1.13.2-1.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xorg-x11-server-debuginfo-7.6_1.13.2-1.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xorg-x11-server-debugsource-7.6_1.13.2-1.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xorg-x11-server-extra-7.6_1.13.2-1.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xorg-x11-server-extra-debuginfo-7.6_1.13.2-1.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xorg-x11-server-sdk-7.6_1.13.2-1.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-Xvnc / xorg-x11-Xvnc-debuginfo / xorg-x11-server / etc");
}
