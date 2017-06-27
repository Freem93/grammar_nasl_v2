#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-446.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(90483);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/13 14:37:11 $");

  script_cve_id("CVE-2016-3190");

  script_name(english:"openSUSE Security Update : cairo (openSUSE-2016-446)");
  script_summary(english:"Check for the openSUSE-2016-446 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"cairo was updated to fix one security issue.

This security issue was fixed :

  - CVE-2016-3190: Out of bounds read in
    fill_xrgb32_lerp_opaque_spans (bsc#971964)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971964"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cairo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cairo-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cairo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cairo-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cairo-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cairo-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcairo-gobject2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcairo-gobject2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcairo-gobject2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcairo-gobject2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcairo-script-interpreter2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcairo-script-interpreter2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcairo-script-interpreter2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcairo-script-interpreter2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcairo2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcairo2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcairo2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcairo2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"cairo-debugsource-1.14.0-7.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cairo-devel-1.14.0-7.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cairo-tools-1.14.0-7.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cairo-tools-debuginfo-1.14.0-7.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libcairo-gobject2-1.14.0-7.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libcairo-gobject2-debuginfo-1.14.0-7.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libcairo-script-interpreter2-1.14.0-7.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libcairo-script-interpreter2-debuginfo-1.14.0-7.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libcairo2-1.14.0-7.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libcairo2-debuginfo-1.14.0-7.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"cairo-devel-32bit-1.14.0-7.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libcairo-gobject2-32bit-1.14.0-7.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libcairo-gobject2-debuginfo-32bit-1.14.0-7.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libcairo-script-interpreter2-32bit-1.14.0-7.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libcairo-script-interpreter2-debuginfo-32bit-1.14.0-7.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libcairo2-32bit-1.14.0-7.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libcairo2-debuginfo-32bit-1.14.0-7.11.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cairo-debugsource / cairo-devel / cairo-devel-32bit / cairo-tools / etc");
}
