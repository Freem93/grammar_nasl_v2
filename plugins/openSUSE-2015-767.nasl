#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-767.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86964);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2017/01/16 15:05:10 $");

  script_cve_id("CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7701", "CVE-2015-7702", "CVE-2015-7703", "CVE-2015-7704", "CVE-2015-7705", "CVE-2015-7848", "CVE-2015-7849", "CVE-2015-7850", "CVE-2015-7851", "CVE-2015-7852", "CVE-2015-7853", "CVE-2015-7854", "CVE-2015-7855", "CVE-2015-7871");
  script_xref(name:"TRA", value:"TRA-2015-04");

  script_name(english:"openSUSE Security Update : ntp (openSUSE-2015-767)");
  script_summary(english:"Check for the openSUSE-2015-767 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This ntp update provides the following security and non security 
fixes :

  - Update to 4.2.8p4 to fix several security issues
    (bsc#951608) :

  - CVE-2015-7871: NAK to the Future: Symmetric association
    authentication bypass via crypto-NAK

  - CVE-2015-7855: decodenetnum() will ASSERT botch instead
    of returning FAIL on some bogus values

  - CVE-2015-7854: Password Length Memory Corruption
    Vulnerability

  - CVE-2015-7853: Invalid length data provided by a custom
    refclock driver could cause a buffer overflow

  - CVE-2015-7852 ntpq atoascii() Memory Corruption
    Vulnerability

  - CVE-2015-7851 saveconfig Directory Traversal
    Vulnerability

  - CVE-2015-7850 remote config logfile-keyfile

  - CVE-2015-7849 trusted key use-after-free

  - CVE-2015-7848 mode 7 loop counter underrun

  - CVE-2015-7701 Slow memory leak in CRYPTO_ASSOC

  - CVE-2015-7703 configuration directives 'pidfile' and
    'driftfile' should only be allowed locally

  - CVE-2015-7704, CVE-2015-7705 Clients that receive a KoD
    should validate the origin timestamp field

  - CVE-2015-7691, CVE-2015-7692, CVE-2015-7702 Incomplete
    autokey data packet length checks

  - obsoletes ntp-memlock.patch.

  - Add a controlkey line to /etc/ntp.conf if one does not
    already exist to allow runtime configuuration via ntpq."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=951608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2015-04"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ntp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntp-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE42.1", reference:"ntp-4.2.8p4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ntp-debuginfo-4.2.8p4-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ntp-debugsource-4.2.8p4-9.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp / ntp-debuginfo / ntp-debugsource");
}
