#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-911.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(87487);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2015-3194", "CVE-2015-3195", "CVE-2015-3196");

  script_name(english:"openSUSE Security Update : openssl (openSUSE-2015-911)");
  script_summary(english:"Check for the openSUSE-2015-911 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openssl fixes the following issues :

Security fixes :

  - CVE-2015-3194: The signature verification routines will
    crash with a NULL pointer dereference if presented with
    an ASN.1 signature using the RSA PSS algorithm and
    absent mask generation function parameter. Since these
    routines are used to verify certificate signature
    algorithms this can be used to crash any certificate
    verification operation and exploited in a DoS attack.
    Any application which performs certificate verification
    is vulnerable including OpenSSL clients and servers
    which enable client authentication. (bsc#957815)

  - CVE-2015-3195: When presented with a malformed
    X509_ATTRIBUTE structure OpenSSL would leak memory. This
    structure is used by the PKCS#7 and CMS routines so any
    application which reads PKCS#7 or CMS data from
    untrusted sources is affected. SSL/TLS is not affected.
    (bsc#957812)

  - CVE-2015-3196: If PSK identity hints are received by a
    multi-threaded client then the values were wrongly
    updated in the parent SSL_CTX structure. This could
    result in a race condition potentially leading to a
    double free of the identify hint data. (bsc#957813)

Non security bugs fixed :

  - Improve S/390 performance on IBM z196 and z13
    (bsc#954256)

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957815"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-hmac-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libopenssl-devel-1.0.1i-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libopenssl1_0_0-1.0.1i-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libopenssl1_0_0-debuginfo-1.0.1i-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libopenssl1_0_0-hmac-1.0.1i-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"openssl-1.0.1i-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"openssl-debuginfo-1.0.1i-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"openssl-debugsource-1.0.1i-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libopenssl-devel-32bit-1.0.1i-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libopenssl1_0_0-32bit-1.0.1i-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.1i-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libopenssl1_0_0-hmac-32bit-1.0.1i-9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libopenssl-devel / libopenssl-devel-32bit / libopenssl1_0_0 / etc");
}
