#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libpciaccess0-5102.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75910);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:10:33 $");

  script_cve_id("CVE-2011-2895");

  script_name(english:"openSUSE Security Update : libpciaccess0 (openSUSE-SU-2011:1299-1)");
  script_summary(english:"Check for the libpciaccess0-5102 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Specially crafted font files could cause a buffer overflow in
applications that use libXfont to load such files (CVE-2011-2895)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-12/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=709851"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libpciaccess0 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpciaccess0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpciaccess0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpciaccess0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpciaccess0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpciaccess0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-libs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-libs-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/05");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"libpciaccess0-7.6-17.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libpciaccess0-debuginfo-7.6-17.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libpciaccess0-devel-7.6-17.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xorg-x11-devel-7.6-17.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xorg-x11-libs-7.6-17.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xorg-x11-libs-debuginfo-7.6-17.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xorg-x11-libs-debugsource-7.6-17.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libpciaccess0-32bit-7.6-17.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libpciaccess0-debuginfo-32bit-7.6-17.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"xorg-x11-devel-32bit-7.6-17.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"xorg-x11-libs-32bit-7.6-17.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"xorg-x11-libs-debuginfo-32bit-7.6-17.18.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpciaccess0 / libpciaccess0-32bit / libpciaccess0-devel / etc");
}
