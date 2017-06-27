#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update ruby-6339.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(42032);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/22 20:42:28 $");

  script_cve_id("CVE-2008-3443", "CVE-2008-3655", "CVE-2008-3656", "CVE-2008-3657", "CVE-2008-3790", "CVE-2008-3905", "CVE-2009-0642", "CVE-2009-1904");

  script_name(english:"openSUSE 10 Security Update : ruby (ruby-6339)");
  script_summary(english:"Check for the ruby-6339 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This ruby update improves return value checks for openssl function
OCSP_basic_verify() (CVE-2009-0642) which allowed an attacker to use
revoked certificates. The entropy of DNS identifiers was increased
(CVE-2008-3905) to avaid spoofing attacks. The code for parsing XML
data was vulnerable to a denial of service bug (CVE-2008-3790). An
attack on algorithm complexity was possible in function
WEBrick::HTTP::DefaultFileHandler() while parsing HTTP requests
(CVE-2008-3656) as well as by using the regex engine (CVE-2008-3443)
causing high CPU load. Ruby's access restriction code (CVE-2008-3655)
as well as safe-level handling using function DL.dlopen()
(CVE-2008-3657) and big decimal handling (CVE-2009-1904) was improved.
Bypassing HTTP basic authentication (authenticate_with_http_digest) is
not possible anymore."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20, 189, 264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-doc-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-test-suite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-tk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.3", reference:"ruby-1.8.6.p369-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"ruby-devel-1.8.6.p369-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"ruby-doc-html-1.8.6.p369-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"ruby-doc-ri-1.8.6.p369-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"ruby-examples-1.8.6.p369-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"ruby-test-suite-1.8.6.p369-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"ruby-tk-1.8.6.p369-0.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby");
}
