#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-207.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(97004);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/28 13:31:42 $");

  script_cve_id("CVE-2016-7444", "CVE-2016-8610", "CVE-2017-5335", "CVE-2017-5336", "CVE-2017-5337");

  script_name(english:"openSUSE Security Update : gnutls (openSUSE-2017-207)");
  script_summary(english:"Check for the openSUSE-2017-207 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for gnutls fixes the following security issues :

  - GnuTLS could have crashed when processing maliciously
    crafted OpenPGP certificates (GNUTLS-SA-2017-2,
    bsc#1018832, CVE-2017-5335, CVE-2017-5337,
    CVE-2017-5336)

  - GnuTLS could have falsely accepted certificates when
    using OCSP (GNUTLS-SA-2016-3, bsc#999646, CVE-2016-7444)

  - GnuTLS could have suffered from 100% CPU load DoS
    attacks by using SSL alert packets during the handshake
    (bsc#1005879, CVE-2016-8610)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1018832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=999646"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnutls packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnutls-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnutls-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls-openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls-openssl27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls-openssl27-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls28-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls28-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls28-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutlsxx-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutlsxx28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutlsxx28-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"gnutls-3.2.15-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gnutls-debuginfo-3.2.15-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gnutls-debugsource-3.2.15-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgnutls-devel-3.2.15-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgnutls-openssl-devel-3.2.15-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgnutls-openssl27-3.2.15-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgnutls-openssl27-debuginfo-3.2.15-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgnutls28-3.2.15-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgnutls28-debuginfo-3.2.15-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgnutlsxx-devel-3.2.15-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgnutlsxx28-3.2.15-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgnutlsxx28-debuginfo-3.2.15-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgnutls-devel-32bit-3.2.15-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgnutls28-32bit-3.2.15-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgnutls28-debuginfo-32bit-3.2.15-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gnutls-3.2.15-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gnutls-debuginfo-3.2.15-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gnutls-debugsource-3.2.15-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgnutls-devel-3.2.15-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgnutls-openssl-devel-3.2.15-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgnutls-openssl27-3.2.15-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgnutls-openssl27-debuginfo-3.2.15-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgnutls28-3.2.15-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgnutls28-debuginfo-3.2.15-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgnutlsxx-devel-3.2.15-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgnutlsxx28-3.2.15-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgnutlsxx28-debuginfo-3.2.15-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libgnutls-devel-32bit-3.2.15-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libgnutls28-32bit-3.2.15-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libgnutls28-debuginfo-32bit-3.2.15-9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnutls / gnutls-debuginfo / gnutls-debugsource / libgnutls-devel / etc");
}
