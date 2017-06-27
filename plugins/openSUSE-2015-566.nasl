#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-566.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(85835);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/09/09 14:39:26 $");

  script_cve_id("CVE-2014-3591", "CVE-2015-0837");

  script_name(english:"openSUSE Security Update : libgcrypt (openSUSE-2015-566)");
  script_summary(english:"Check for the openSUSE-2015-566 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes two security vulnerabilities (bsc#920057) :

  - Use ciphertext blinding for Elgamal decryption
    [CVE-2014-3591]. See
    http://www.cs.tau.ac.il/~tromer/radioexp/ for details.

  - Fixed data-dependent timing variations in modular
    exponentiation [related to CVE-2015-0837, Last-Level
    Cache Side-Channel Attacks are Practical]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.cs.tau.ac.il/~tromer/radioexp/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=920057"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libgcrypt packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-cavs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-cavs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-devel-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt11-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt11-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20-hmac-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/08");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"libgcrypt-debugsource-1.5.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgcrypt-devel-1.5.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgcrypt-devel-debuginfo-1.5.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgcrypt11-1.5.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libgcrypt11-debuginfo-1.5.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libgcrypt-devel-32bit-1.5.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libgcrypt-devel-debuginfo-32bit-1.5.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libgcrypt11-32bit-1.5.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libgcrypt11-debuginfo-32bit-1.5.4-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgcrypt-cavs-1.6.1-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgcrypt-cavs-debuginfo-1.6.1-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgcrypt-debugsource-1.6.1-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgcrypt-devel-1.6.1-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgcrypt-devel-debuginfo-1.6.1-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgcrypt20-1.6.1-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgcrypt20-debuginfo-1.6.1-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgcrypt20-hmac-1.6.1-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgcrypt-devel-32bit-1.6.1-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgcrypt-devel-debuginfo-32bit-1.6.1-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgcrypt20-32bit-1.6.1-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgcrypt20-debuginfo-32bit-1.6.1-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgcrypt20-hmac-32bit-1.6.1-8.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgcrypt-debugsource / libgcrypt-devel / libgcrypt-devel-32bit / etc");
}
