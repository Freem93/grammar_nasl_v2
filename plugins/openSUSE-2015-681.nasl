#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-681.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86622);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/11/20 15:06:53 $");

  script_cve_id("CVE-2015-5333", "CVE-2015-5334");

  script_name(english:"openSUSE Security Update : libressl (openSUSE-2015-681)");
  script_summary(english:"Check for the openSUSE-2015-681 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libressl was updated to fix two security issues.

These security issues were fixed :

  - CVE-2015-5333: Memory leak when decoding X.509
    certificates (boo#950707)

  - CVE-2015-5334: Buffer overflow when decoding X.509
    certificates (boo#950708)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=950707"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=950708"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libressl packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto34-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto34-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto34-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto36-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto36-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto36-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl33");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl33-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl33-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl33-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl37-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl37-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl37-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls9-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls9-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls9-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"libcrypto34-2.2.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libcrypto34-debuginfo-2.2.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libressl-2.2.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libressl-debuginfo-2.2.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libressl-debugsource-2.2.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libressl-devel-2.2.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libssl33-2.2.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libssl33-debuginfo-2.2.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libtls4-2.2.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libtls4-debuginfo-2.2.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libcrypto34-32bit-2.2.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libcrypto34-debuginfo-32bit-2.2.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libressl-devel-32bit-2.2.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libssl33-32bit-2.2.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libssl33-debuginfo-32bit-2.2.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libtls4-32bit-2.2.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libtls4-debuginfo-32bit-2.2.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libcrypto36-2.3.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libcrypto36-debuginfo-2.3.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libressl-2.3.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libressl-debuginfo-2.3.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libressl-debugsource-2.3.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libressl-devel-2.3.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libssl37-2.3.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libssl37-debuginfo-2.3.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libtls9-2.3.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libtls9-debuginfo-2.3.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libcrypto36-32bit-2.3.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libcrypto36-debuginfo-32bit-2.3.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libressl-devel-32bit-2.3.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libssl37-32bit-2.3.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libssl37-debuginfo-32bit-2.3.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libtls9-32bit-2.3.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libtls9-debuginfo-32bit-2.3.0-3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcrypto34 / libcrypto34-32bit / libcrypto34-debuginfo / etc");
}
