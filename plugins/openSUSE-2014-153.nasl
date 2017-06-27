#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-153.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75265);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2013-7107");
  script_osvdb_id(101021);

  script_name(english:"openSUSE Security Update : icinga (openSUSE-SU-2014:0269-1)");
  script_summary(english:"Check for the openSUSE-2014-153 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following security issue with icinga :

  - bnc#859424: Fixed vulnerability against CSRF attacks
    (CVE-2013-7107)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-02/msg00061.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=859424"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected icinga packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-www-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:monitoring-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:monitoring-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"icinga-1.10.2-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icinga-debuginfo-1.10.2-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icinga-debugsource-1.10.2-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icinga-devel-1.10.2-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icinga-idoutils-1.10.2-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icinga-idoutils-debuginfo-1.10.2-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icinga-idoutils-mysql-1.10.2-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icinga-idoutils-oracle-1.10.2-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icinga-idoutils-pgsql-1.10.2-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icinga-plugins-downtimes-1.10.2-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icinga-plugins-eventhandlers-1.10.2-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icinga-www-1.10.2-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icinga-www-debuginfo-1.10.2-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"monitoring-tools-1.10.2-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"monitoring-tools-debuginfo-1.10.2-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"icinga-1.10.2-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"icinga-debuginfo-1.10.2-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"icinga-debugsource-1.10.2-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"icinga-devel-1.10.2-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"icinga-idoutils-1.10.2-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"icinga-idoutils-debuginfo-1.10.2-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"icinga-idoutils-mysql-1.10.2-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"icinga-idoutils-oracle-1.10.2-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"icinga-idoutils-pgsql-1.10.2-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"icinga-plugins-downtimes-1.10.2-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"icinga-plugins-eventhandlers-1.10.2-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"icinga-www-1.10.2-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"icinga-www-debuginfo-1.10.2-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"monitoring-tools-1.10.2-4.10.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"monitoring-tools-debuginfo-1.10.2-4.10.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icinga / icinga-debuginfo / icinga-debugsource / icinga-devel / etc");
}
