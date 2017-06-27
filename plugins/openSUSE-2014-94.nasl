#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-94.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75412);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2013-4549");

  script_name(english:"openSUSE Security Update : libqt5-qtbase (openSUSE-SU-2014:0173-1)");
  script_summary(english:"Check for the openSUSE-2014-94 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - added patches :

  - disallow-deep-or-widely-nested-entity-references.patch:
    upstream fix for bnc#856832 and CVE-2013-4549: xml
    entity expansion attacks"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-01/msg00104.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-01/msg00106.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=856832"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libqt5-qtbase packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-sql-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-sql-mysql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-sql-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-sql-mysql-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-sql-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-sql-postgresql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-sql-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-sql-postgresql-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-sql-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-sql-sqlite-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-sql-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-sql-sqlite-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-sql-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-sql-unixODBC-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-sql-unixODBC-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-sql-unixODBC-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/22");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"libQt5Gui5-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libQt5Gui5-debuginfo-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libQt5Sql5-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libQt5Sql5-debuginfo-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libQt5Test5-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libQt5Test5-debuginfo-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libQt5Widgets5-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libQt5Widgets5-debuginfo-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt5-qtbase-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt5-qtbase-debuginfo-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt5-qtbase-debugsource-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt5-qtbase-devel-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt5-qtbase-devel-debuginfo-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt5-qtbase-private-headers-devel-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt5-sql-mysql-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt5-sql-mysql-debuginfo-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt5-sql-postgresql-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt5-sql-postgresql-debuginfo-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt5-sql-sqlite-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt5-sql-sqlite-debuginfo-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt5-sql-unixODBC-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libqt5-sql-unixODBC-debuginfo-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libQt5Gui5-32bit-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libQt5Gui5-debuginfo-32bit-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libQt5Sql5-32bit-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libQt5Sql5-debuginfo-32bit-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libQt5Test5-32bit-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libQt5Test5-debuginfo-32bit-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libQt5Widgets5-32bit-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libQt5Widgets5-debuginfo-32bit-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libqt5-qtbase-32bit-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libqt5-qtbase-debuginfo-32bit-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libqt5-sql-mysql-32bit-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libqt5-sql-mysql-debuginfo-32bit-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libqt5-sql-postgresql-32bit-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libqt5-sql-postgresql-debuginfo-32bit-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libqt5-sql-sqlite-32bit-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libqt5-sql-sqlite-debuginfo-32bit-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libqt5-sql-unixODBC-32bit-5.1.1-6.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libqt5-sql-unixODBC-debuginfo-32bit-5.1.1-6.7") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libQt5Gui5-32bit / libQt5Gui5 / libQt5Gui5-debuginfo-32bit / etc");
}
