#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update mono-core-2373.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27349);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/06/13 20:31:03 $");

  script_name(english:"openSUSE 10 Security Update : mono-core (mono-core-2373)");
  script_summary(english:"Check for the mono-core-2373 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"By appending spaces to URLs and attackers could download the source
code of scripts that normally get executed by the web server."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mono-core packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bytefx-data-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ibm-data-db2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-basic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-core-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-data-firebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-data-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-data-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-data-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-data-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-jscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-locale-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-nunit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-winforms");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/11");
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
if (release !~ "^(SUSE10\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"bytefx-data-mysql-1.1.13.8-2.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"ibm-data-db2-1.1.13.8-2.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"mono-basic-1.1.13.8-2.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"mono-core-1.1.13.8-2.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"mono-data-1.1.13.8-2.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"mono-data-firebird-1.1.13.8-2.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"mono-data-oracle-1.1.13.8-2.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"mono-data-postgresql-1.1.13.8-2.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"mono-data-sqlite-1.1.13.8-2.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"mono-data-sybase-1.1.13.8-2.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"mono-devel-1.1.13.8-2.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"mono-extras-1.1.13.8-2.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"mono-jscript-1.1.13.8-2.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"mono-locale-extras-1.1.13.8-2.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"mono-nunit-1.1.13.8-2.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"mono-web-1.1.13.8-2.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"mono-winforms-1.1.13.8-2.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"mono-core-32bit-1.1.13.8-2.15") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mono");
}
