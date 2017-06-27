#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2011-12.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74517);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2011-3153");

  script_name(english:"openSUSE Security Update : lightdm (openSUSE-2011-12)");
  script_summary(english:"Check for the openSUSE-2011-12 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerabilities were discovered for the lightdm packages in openSUSE
version 12.1."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=728627"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=730062"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected lightdm packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblightdm-gobject-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblightdm-gobject-1-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblightdm-qt-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblightdm-qt-1-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm-gobject-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm-gtk-greeter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm-gtk-greeter-branding-openSUSE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm-gtk-greeter-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm-gtk-greeter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm-qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm-qt-greeter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm-qt-greeter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/22");
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

if ( rpm_check(release:"SUSE12.1", reference:"liblightdm-gobject-1-0-1.0.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"liblightdm-gobject-1-0-debuginfo-1.0.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"liblightdm-qt-1-0-1.0.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"liblightdm-qt-1-0-debuginfo-1.0.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lightdm-1.0.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lightdm-debuginfo-1.0.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lightdm-debugsource-1.0.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lightdm-gobject-devel-1.0.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lightdm-gtk-greeter-1.0.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lightdm-gtk-greeter-branding-openSUSE-12.1-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lightdm-gtk-greeter-branding-upstream-1.0.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lightdm-gtk-greeter-debuginfo-1.0.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lightdm-lang-1.0.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lightdm-qt-devel-1.0.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lightdm-qt-greeter-1.0.6-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lightdm-qt-greeter-debuginfo-1.0.6-1.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lightdm-gtk-greeter-branding-openSUSE / liblightdm-qt-1-0-debuginfo / etc");
}
