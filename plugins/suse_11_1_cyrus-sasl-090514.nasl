#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update cyrus-sasl-880.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(40209);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/06/13 19:49:33 $");

  script_cve_id("CVE-2009-0688");

  script_name(english:"openSUSE Security Update : cyrus-sasl (cyrus-sasl-880)");
  script_summary(english:"Check for the cyrus-sasl-880 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of cyrus-sasl improves the output of function
sasl_encode64() by appending a 0 for string termination. The impact
depends on the application that uses sasl_encode64(). (CVE-2009-0688)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=499104"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cyrus-sasl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-crammd5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-crammd5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-digestmd5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-digestmd5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-gssapi-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-ntlm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-otp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-otp-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-plain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cyrus-sasl-plain-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"cyrus-sasl-2.1.22-182.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"cyrus-sasl-crammd5-2.1.22-182.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"cyrus-sasl-devel-2.1.22-182.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"cyrus-sasl-digestmd5-2.1.22-182.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"cyrus-sasl-gssapi-2.1.22-182.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"cyrus-sasl-ntlm-2.1.22-182.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"cyrus-sasl-otp-2.1.22-182.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"cyrus-sasl-plain-2.1.22-182.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"cyrus-sasl-32bit-2.1.22-182.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"cyrus-sasl-crammd5-32bit-2.1.22-182.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"cyrus-sasl-devel-32bit-2.1.22-182.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"cyrus-sasl-digestmd5-32bit-2.1.22-182.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"cyrus-sasl-gssapi-32bit-2.1.22-182.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"cyrus-sasl-otp-32bit-2.1.22-182.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"cyrus-sasl-plain-32bit-2.1.22-182.2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cyrus_sasl");
}
