#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-850.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75199);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-4509");

  script_name(english:"openSUSE Security Update : ibus (openSUSE-SU-2013:1686-1)");
  script_summary(english:"Check for the openSUSE-2013-850 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"- This is an additional fix patch for ibus to avoid the wrong
IBus.InputPurpose.PASSWORD advertisement, which leads to the password
text appearance on GNOME3 lockscreen (bnc#847718)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-11/msg00036.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=847718"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ibus packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ibus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ibus-branding-openSUSE-KDE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ibus-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ibus-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ibus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ibus-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ibus-gtk-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ibus-gtk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ibus-gtk-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ibus-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ibus-gtk3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ibus-gtk3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ibus-gtk3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ibus-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libibus-1_0-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libibus-1_0-5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libibus-1_0-5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libibus-1_0-5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-ibus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-IBus-1_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/07");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"ibus-1.5.4-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ibus-branding-openSUSE-KDE-1.5.4-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ibus-debuginfo-1.5.4-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ibus-debugsource-1.5.4-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ibus-devel-1.5.4-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ibus-gtk-1.5.4-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ibus-gtk-debuginfo-1.5.4-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ibus-gtk3-1.5.4-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ibus-gtk3-debuginfo-1.5.4-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ibus-lang-1.5.4-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libibus-1_0-5-1.5.4-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libibus-1_0-5-debuginfo-1.5.4-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-ibus-1.5.4-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"typelib-1_0-IBus-1_0-1.5.4-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"ibus-gtk-32bit-1.5.4-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"ibus-gtk-debuginfo-32bit-1.5.4-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"ibus-gtk3-32bit-1.5.4-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"ibus-gtk3-debuginfo-32bit-1.5.4-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libibus-1_0-5-32bit-1.5.4-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libibus-1_0-5-debuginfo-32bit-1.5.4-4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ibus");
}
