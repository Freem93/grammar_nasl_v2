#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-125.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(81287);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/03/11 13:51:32 $");

  script_cve_id("CVE-2014-3707", "CVE-2014-8150");

  script_name(english:"openSUSE Security Update : curl (openSUSE-2015-125)");
  script_summary(english:"Check for the openSUSE-2015-125 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"was updated to version 7.40.0 to fix two security issues.

These security issues were fixed :

  - CVE-2014-8150: CRLF injection vulnerability in libcurl
    6.0 through 7.x before 7.40.0, when using an HTTP proxy,
    allowed remote attackers to inject arbitrary HTTP
    headers and conduct HTTP response splitting attacks via
    CRLF sequences in a URL (bnc#911363).

  - CVE-2014-3707: The curl_easy_duphandle function in
    libcurl 7.17.1 through 7.38.0, when running with the
    CURLOPT_COPYPOSTFIELDS option, did not properly copy
    HTTP POST data for an easy handle, which triggered an
    out-of-bounds read that allowed remote web servers to
    read sensitive memory information (bnc#901924).

These non-security issues were fixed :

- http_digest: Added support for Windows SSPI based authentication

  - version info: Added Kerberos V5 to the supported
    features

  - Makefile: Added VC targets for WinIDN

  - SSL: Add PEM format support for public key pinning

  - smtp: Added support for the conversion of Unix newlines
    during mail send

  - smb: Added initial support for the SMB/CIFS protocol

  - Added support for HTTP over unix domain sockets,

  - via CURLOPT_UNIX_SOCKET_PATH and --unix-socket

  - sasl: Added support for GSS-API based Kerberos V5
    authentication"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=901924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=911363"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected curl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:curl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/11");
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

if ( rpm_check(release:"SUSE13.1", reference:"curl-7.40.0-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"curl-debuginfo-7.40.0-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"curl-debugsource-7.40.0-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libcurl-devel-7.40.0-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libcurl4-7.40.0-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libcurl4-debuginfo-7.40.0-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libcurl4-32bit-7.40.0-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libcurl4-debuginfo-32bit-7.40.0-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"curl-7.40.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"curl-debuginfo-7.40.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"curl-debugsource-7.40.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libcurl-devel-7.40.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libcurl4-7.40.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libcurl4-debuginfo-7.40.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libcurl4-32bit-7.40.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libcurl4-debuginfo-32bit-7.40.0-4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / curl-debuginfo / curl-debugsource / libcurl-devel / etc");
}
