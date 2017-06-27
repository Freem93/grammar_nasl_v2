#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-139.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74897);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2013-0255");
  script_osvdb_id(89935);

  script_name(english:"openSUSE Security Update : postgresql91 (openSUSE-SU-2013:0318-1)");
  script_summary(english:"Check for the openSUSE-2013-139 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"PostgreSQL was updated to version 9.1.8 (bnc#802679) :

  - Prevent execution of enum_recv from SQL (CVE-2013-0255).

  - Fix multiple problems in detection of when a consistent
    database state has been reached during WAL replay

  - Update minimum recovery point when truncating a relation
    file

  - Fix recycling of WAL segments after changing recovery
    target timeline

  - Fix missing cancellations in hot standby mode

  - See the release notes for the rest of the changes:
    http://www.postgresql.org/docs/9.1/static/release-9-1-8.
    html /usr/share/doc/packages/postgresql/HISTORY

  - Remove postgresql91-full.spec.in and use
    postgresql91.spec as the master for generating
    postgresql91-libs.spec."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-02/msg00059.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/9.1/static/release-9-1-8.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=802679"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql91 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql91");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql91-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql91-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql91-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql91-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql91-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql91-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql91-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql91-devel-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql91-libs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql91-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql91-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql91-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql91-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql91-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql91-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql91-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql91-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/13");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"libecpg6-9.1.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libecpg6-debuginfo-9.1.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libpq5-9.1.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libpq5-debuginfo-9.1.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"postgresql91-9.1.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"postgresql91-contrib-9.1.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"postgresql91-contrib-debuginfo-9.1.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"postgresql91-debuginfo-9.1.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"postgresql91-debugsource-9.1.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"postgresql91-devel-9.1.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"postgresql91-devel-debuginfo-9.1.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"postgresql91-libs-debugsource-9.1.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"postgresql91-plperl-9.1.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"postgresql91-plperl-debuginfo-9.1.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"postgresql91-plpython-9.1.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"postgresql91-plpython-debuginfo-9.1.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"postgresql91-pltcl-9.1.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"postgresql91-pltcl-debuginfo-9.1.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"postgresql91-server-9.1.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"postgresql91-server-debuginfo-9.1.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libecpg6-32bit-9.1.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libecpg6-debuginfo-32bit-9.1.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libpq5-32bit-9.1.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libpq5-debuginfo-32bit-9.1.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"postgresql91-devel-32bit-9.1.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"postgresql91-devel-debuginfo-32bit-9.1.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libecpg6-9.1.8-16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libecpg6-debuginfo-9.1.8-16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpq5-9.1.8-16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpq5-debuginfo-9.1.8-16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql91-9.1.8-16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql91-contrib-9.1.8-16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql91-contrib-debuginfo-9.1.8-16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql91-debuginfo-9.1.8-16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql91-debugsource-9.1.8-16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql91-devel-9.1.8-16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql91-devel-debuginfo-9.1.8-16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql91-libs-debugsource-9.1.8-16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql91-plperl-9.1.8-16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql91-plperl-debuginfo-9.1.8-16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql91-plpython-9.1.8-16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql91-plpython-debuginfo-9.1.8-16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql91-pltcl-9.1.8-16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql91-pltcl-debuginfo-9.1.8-16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql91-server-9.1.8-16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"postgresql91-server-debuginfo-9.1.8-16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libecpg6-32bit-9.1.8-16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libecpg6-debuginfo-32bit-9.1.8-16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libpq5-32bit-9.1.8-16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libpq5-debuginfo-32bit-9.1.8-16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"postgresql91-devel-32bit-9.1.8-16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"postgresql91-devel-debuginfo-32bit-9.1.8-16.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql91");
}
