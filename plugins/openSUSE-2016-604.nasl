#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-604.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91274);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:37:11 $");

  script_cve_id("CVE-2015-3194", "CVE-2015-3195", "CVE-2015-5333", "CVE-2015-5334");

  script_name(english:"openSUSE Security Update : libressl (openSUSE-2016-604)");
  script_summary(english:"Check for the openSUSE-2016-604 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This libressl update to version 2.2.7 fixes the following issues :

Security issues fixed :

  - Fix multiple vulnerabilities in libcrypto relating to
    ASN.1 and encoding. [boo#978492, boo#977584]

  - CVE-2015-3194: Certificate verify crash with missing PSS
    parameter (boo#957815)

  - CVE-2015-3195: X509_ATTRIBUTE memory leak (boo#957812)

  - CVE-2015-5333: Memory Leak (boo#950707)

  - CVE-2015-5334: Buffer Overflow (boo#950708)"
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
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978492"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libressl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto34-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto34-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto34-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl33");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl33-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl33-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl33-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/20");
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

if ( rpm_check(release:"SUSE13.2", reference:"libcrypto34-2.2.7-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libcrypto34-debuginfo-2.2.7-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libressl-2.2.7-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libressl-debuginfo-2.2.7-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libressl-debugsource-2.2.7-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libressl-devel-2.2.7-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libssl33-2.2.7-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libssl33-debuginfo-2.2.7-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libtls4-2.2.7-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libtls4-debuginfo-2.2.7-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libcrypto34-32bit-2.2.7-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libcrypto34-debuginfo-32bit-2.2.7-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libressl-devel-32bit-2.2.7-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libssl33-32bit-2.2.7-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libssl33-debuginfo-32bit-2.2.7-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libtls4-32bit-2.2.7-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libtls4-debuginfo-32bit-2.2.7-2.13.1") ) flag++;

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
