#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-565.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(90935);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/10/13 14:37:11 $");

  script_cve_id("CVE-2016-0702", "CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2108", "CVE-2016-2109");

  script_name(english:"openSUSE Security Update : libopenssl0_9_8 (openSUSE-2016-565)");
  script_summary(english:"Check for the openSUSE-2016-565 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libopenssl0_9_8 fixes the following issues :

  - CVE-2016-2105: EVP_EncodeUpdate overflow (bsc#977614)

  - CVE-2016-2106: EVP_EncryptUpdate overflow (bsc#977615)

  - CVE-2016-2108: Memory corruption in the ASN.1 encoder
    (bsc#977617)

  - CVE-2016-2109: ASN.1 BIO excessive memory allocation
    (bsc#976942)

  - CVE-2016-0702: Side channel attack on modular
    exponentiation 'CacheBleed' (bsc#968050)

  - bsc#976943: Buffer overrun in ASN1_parse"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=976942"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=976943"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977615"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977617"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libopenssl0_9_8 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl0_9_8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl0_9_8-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl0_9_8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl0_9_8-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl0_9_8-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/06");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"libopenssl0_9_8-0.9.8zh-9.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libopenssl0_9_8-debuginfo-0.9.8zh-9.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libopenssl0_9_8-debugsource-0.9.8zh-9.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libopenssl0_9_8-32bit-0.9.8zh-9.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libopenssl0_9_8-debuginfo-32bit-0.9.8zh-9.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libopenssl0_9_8-0.9.8zh-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libopenssl0_9_8-debuginfo-0.9.8zh-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libopenssl0_9_8-debugsource-0.9.8zh-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libopenssl0_9_8-32bit-0.9.8zh-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libopenssl0_9_8-debuginfo-32bit-0.9.8zh-17.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libopenssl0_9_8 / libopenssl0_9_8-32bit / libopenssl0_9_8-debuginfo / etc");
}
