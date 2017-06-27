#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-11.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74891);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/08/10 14:35:57 $");

  script_cve_id("CVE-2012-5624");
  script_osvdb_id(85927, 88294);

  script_name(english:"openSUSE Security Update : libqt4 (openSUSE-SU-2013:0154-1)");
  script_summary(english:"Check for the openSUSE-2013-11 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libqt4 received a fix for a security issue :

  - avoid redirect to file url scheme in XMLHttpRequests
    (bnc#793194, CVE-2012-5624)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-01/msg00045.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=793194"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libqt4 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-devel-doc-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-devel-doc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-devel-doc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-qt3support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-qt3support-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-qt3support-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-qt3support-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-mysql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-mysql-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-plugins-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-postgresql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-postgresql-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-sqlite-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-sqlite-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-unixODBC-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-unixODBC-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-unixODBC-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-x11-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-x11-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qt4-x11-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qt4-x11-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"libqt4-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libqt4-debuginfo-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libqt4-debugsource-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libqt4-devel-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libqt4-devel-debuginfo-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libqt4-devel-doc-data-4.8.1-2.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libqt4-devel-doc-debuginfo-4.8.1-2.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libqt4-devel-doc-debugsource-4.8.1-2.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libqt4-private-headers-devel-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libqt4-qt3support-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libqt4-qt3support-debuginfo-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libqt4-sql-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libqt4-sql-debuginfo-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libqt4-sql-mysql-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libqt4-sql-mysql-debuginfo-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libqt4-sql-plugins-debugsource-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libqt4-sql-postgresql-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libqt4-sql-postgresql-debuginfo-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libqt4-sql-sqlite-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libqt4-sql-sqlite-debuginfo-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libqt4-sql-unixODBC-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libqt4-sql-unixODBC-debuginfo-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libqt4-x11-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libqt4-x11-debuginfo-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"qt4-x11-tools-4.8.1-2.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"qt4-x11-tools-debuginfo-4.8.1-2.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libqt4-32bit-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libqt4-debuginfo-32bit-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libqt4-qt3support-32bit-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libqt4-qt3support-debuginfo-32bit-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libqt4-sql-32bit-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libqt4-sql-debuginfo-32bit-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libqt4-sql-mysql-32bit-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libqt4-sql-mysql-debuginfo-32bit-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libqt4-sql-postgresql-32bit-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libqt4-sql-postgresql-debuginfo-32bit-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libqt4-sql-sqlite-32bit-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libqt4-sql-sqlite-debuginfo-32bit-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libqt4-sql-unixODBC-32bit-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libqt4-sql-unixODBC-debuginfo-32bit-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libqt4-x11-32bit-4.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libqt4-x11-debuginfo-32bit-4.8.1-2.8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libqt4");
}
