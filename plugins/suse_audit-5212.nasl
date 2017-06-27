#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update audit-5212.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(32076);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/06/13 20:06:05 $");

  script_cve_id("CVE-2008-1628");

  script_name(english:"openSUSE 10 Security Update : audit (audit-5212)");
  script_summary(english:"Check for the audit-5212 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A bug in the audit_log_user_command() function could lead to a buffer
overflow. No program in openSUSE uses that function. Third-party
applications could be affected though (CVE-2008-1628)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected audit packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:P/I:P/A:P");
  script_cwe_id(119,264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:audit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:audit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:audit-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:audit-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:audit-libs-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE10.3", reference:"audit-1.5.5-13.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"audit-devel-1.5.5-13.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"audit-libs-1.5.5-13.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"audit-libs-python-1.5.5-20.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"audit-libs-32bit-1.5.5-13.4") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "audit / audit-devel / audit-libs / audit-libs-32bit / etc");
}
