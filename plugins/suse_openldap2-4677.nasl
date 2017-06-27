#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openldap2-4677.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(28327);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/06/13 20:31:04 $");

  script_cve_id("CVE-2007-5707", "CVE-2007-5708");

  script_name(english:"openSUSE 10 Security Update : openldap2 (openldap2-4677)");
  script_summary(english:"Check for the openldap2-4677 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes multiple flaws that could cause slapd to crash
(CVE-2007-5707, CVE-2007-5708)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openldap2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-back-meta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-back-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/26");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"openldap2-2.3.19-18.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"openldap2-back-meta-2.3.19-18.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"openldap2-back-perl-2.3.19-18.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"openldap2-devel-2.3.19-18.14") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"openldap2-devel-32bit-2.3.19-18.14") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"openldap2-2.3.27-27") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"openldap2-back-meta-2.3.27-27") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"openldap2-back-perl-2.3.27-27") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"openldap2-devel-2.3.27-27") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"openldap2-devel-32bit-2.3.27-27") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"openldap2-2.3.37-7.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"openldap2-back-meta-2.3.37-7.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"openldap2-back-perl-2.3.37-7.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"openldap2-devel-2.3.37-20.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"openldap2-devel-32bit-2.3.37-20.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openldap2 / openldap2-back-meta / openldap2-back-perl / etc");
}
