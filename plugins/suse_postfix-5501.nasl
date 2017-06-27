#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update postfix-5501.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(33897);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/22 20:42:28 $");

  script_cve_id("CVE-2008-2936", "CVE-2008-2937");

  script_name(english:"openSUSE 10 Security Update : postfix (postfix-5501)");
  script_summary(english:"Check for the postfix-5501 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A (local) privilege escalation vulnerability as well as a mailbox
ownership problem has been fixed in postfix. CVE-2008-2936 and
CVE-2008-2937 have been assigned to this problem."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postfix packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_cwe_id(200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postfix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postfix-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postfix-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postfix-postgresql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.2", reference:"postfix-2.3.2-32") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"postfix-devel-2.3.2-32") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"postfix-mysql-2.3.2-32") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"postfix-postgresql-2.3.2-32") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"postfix-2.4.5-20.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"postfix-devel-2.4.5-20.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"postfix-mysql-2.4.5-20.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"postfix-postgresql-2.4.5-20.4") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postfix");
}
