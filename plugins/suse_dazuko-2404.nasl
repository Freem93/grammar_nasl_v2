#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update dazuko-2404.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27195);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/06/13 20:06:06 $");

  script_name(english:"openSUSE 10 Security Update : dazuko (dazuko-2404)");
  script_summary(english:"Check for the dazuko-2404 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This patch updates the Dazuko kernel module to version 2.3.2. 

Several memory leaks and stability issues have been fixed."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dazuko packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dazuko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dazuko-kmp-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dazuko-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dazuko-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/14");
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
if (release !~ "^(SUSE10\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.2", reference:"dazuko-2.3.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"dazuko-kmp-bigsmp-2.3.2_2.6.18.2_34-3.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"dazuko-kmp-default-2.3.2_2.6.18.2_34-3.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"dazuko-kmp-xen-2.3.2_2.6.18.2_34-3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dazuko");
}
