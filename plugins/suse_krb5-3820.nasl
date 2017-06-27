#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update krb5-3820.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27309);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/06/13 20:11:36 $");

  script_cve_id("CVE-2007-2442", "CVE-2007-2443", "CVE-2007-2798");

  script_name(english:"openSUSE 10 Security Update : krb5 (krb5-3820)");
  script_summary(english:"Check for the krb5-3820 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a stack-based buffer overflow in kadmind which can
be exploited by authenticated remote users to gain root.
(CVE-2007-2798) Additionally two bugs in the RPC library of kadmind
were fixed that can lead to remote system compromise. (CVE-2007-2442,
CVE-2007-2443) Note that third-party applications using the RPC
library are vulnerable, too."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"krb5-1.4.3-19.22") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"krb5-devel-1.4.3-19.22") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"krb5-server-1.4.3-19.22") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"krb5-32bit-1.4.3-19.22") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"krb5-devel-32bit-1.4.3-19.22") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"krb5-1.5.1-23.6") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"krb5-devel-1.5.1-23.6") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"krb5-server-1.5.1-23.6") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"krb5-32bit-1.5.1-23.6") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"krb5-devel-32bit-1.5.1-23.6") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5");
}
