#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update km_drm-4484.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27303);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/06/13 20:11:36 $");

  script_name(english:"openSUSE 10 Security Update : km_drm (km_drm-4484)");
  script_summary(english:"Check for the km_drm-4484 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following issues: X Font Server build_range()
Integer Overflow Vulnerability [IDEF2708], X Font Server swap_char2b()
Heap Overflow Vulnerability [IDEF2709], Composite extension buffer
overflow."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected km_drm packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-Xprt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-Xvnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-driver-options");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-fonts-100dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-fonts-75dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-fonts-cyrillic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-fonts-scalable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-fonts-syriac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-glx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-sdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"xorg-x11-6.9.0-50.52") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xorg-x11-Xnest-6.9.0-50.52") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xorg-x11-Xprt-6.9.0-50.52") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xorg-x11-Xvfb-6.9.0-50.52") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xorg-x11-Xvnc-6.9.0-50.52") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xorg-x11-devel-6.9.0-50.52") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xorg-x11-driver-options-6.9.0-50.52") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xorg-x11-fonts-100dpi-6.9.0-50.52") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xorg-x11-fonts-75dpi-6.9.0-50.52") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xorg-x11-fonts-cyrillic-6.9.0-50.52") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xorg-x11-fonts-scalable-6.9.0-50.52") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xorg-x11-fonts-syriac-6.9.0-50.52") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xorg-x11-libs-6.9.0-50.52") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xorg-x11-man-6.9.0-50.52") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xorg-x11-sdk-6.9.0-50.52") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xorg-x11-server-6.9.0-50.52") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xorg-x11-server-glx-6.9.0-50.52") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"xorg-x11-devel-32bit-6.9.0-50.52") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"xorg-x11-libs-32bit-6.9.0-50.52") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"xorg-x11-7.2-28") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"xorg-x11-Xvnc-7.1-33.4") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"xorg-x11-devel-7.2-23") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"xorg-x11-libs-7.2-23") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"xorg-x11-server-7.2-30.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"xorg-x11-server-sdk-7.2-30.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"xorg-x11-devel-32bit-7.2-23") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"xorg-x11-libs-32bit-7.2-23") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xorg-x11-7.2-135.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xorg-x11-Xvnc-7.1-91.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xorg-x11-devel-7.2-103.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xorg-x11-libs-7.2-103.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xorg-x11-server-7.2-143.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xorg-x11-server-extra-7.2-143.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xorg-x11-server-sdk-7.2-143.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"xorg-x11-devel-32bit-7.2-103.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"xorg-x11-libs-32bit-7.2-103.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11 / xorg-x11-Xnest / xorg-x11-Xprt / xorg-x11-Xvfb / etc");
}
