#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-100.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(96545);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/01/19 15:37:19 $");

  script_cve_id("CVE-2015-8010", "CVE-2016-9566");

  script_name(english:"openSUSE Security Update : icinga (openSUSE-2017-100)");
  script_summary(english:"Check for the openSUSE-2017-100 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for icinga includes various upstream fixes and the
following security security fixes :

  - icinga was updated to version 1.14.0

  - the classic-UI was vulnerable to a cross site scripting
    attack (CVE-2015-8010, boo#952777)

  - A user with nagios privileges could have gained root
    privileges by placing a symbolic link at the logfile
    location (CVE-2016-9566, boo#1014637)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1014637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=952777"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected icinga packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-idoutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-idoutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-idoutils-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-idoutils-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-idoutils-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-plugins-downtimes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-plugins-eventhandlers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-www");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-www-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-www-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:monitoring-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:monitoring-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"icinga-1.14.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"icinga-debuginfo-1.14.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"icinga-debugsource-1.14.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"icinga-devel-1.14.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"icinga-idoutils-1.14.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"icinga-idoutils-debuginfo-1.14.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"icinga-idoutils-mysql-1.14.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"icinga-idoutils-oracle-1.14.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"icinga-idoutils-pgsql-1.14.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"icinga-plugins-downtimes-1.14.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"icinga-plugins-eventhandlers-1.14.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"icinga-www-1.14.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"icinga-www-config-1.14.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"icinga-www-debuginfo-1.14.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"monitoring-tools-1.14.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"monitoring-tools-debuginfo-1.14.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"icinga-1.14.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"icinga-debuginfo-1.14.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"icinga-debugsource-1.14.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"icinga-devel-1.14.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"icinga-idoutils-1.14.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"icinga-idoutils-debuginfo-1.14.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"icinga-idoutils-mysql-1.14.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"icinga-idoutils-oracle-1.14.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"icinga-idoutils-pgsql-1.14.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"icinga-plugins-downtimes-1.14.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"icinga-plugins-eventhandlers-1.14.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"icinga-www-1.14.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"icinga-www-config-1.14.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"icinga-www-debuginfo-1.14.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"monitoring-tools-1.14.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"monitoring-tools-debuginfo-1.14.0-4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icinga / icinga-debuginfo / icinga-debugsource / icinga-devel / etc");
}
