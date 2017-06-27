#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-253.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(88926);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2007-4772", "CVE-2016-0766", "CVE-2016-0773");

  script_name(english:"openSUSE Security Update : postgresql93 (openSUSE-2016-253)");
  script_summary(english:"Check for the openSUSE-2016-253 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for postgresql93 fixes the following issues :

  - Security and bugfix release 9.3.11 :

  - Fix infinite loops and buffer-overrun problems in
    regular expressions (CVE-2016-0773, boo#966436).

  - Fix regular-expression compiler to handle loops of
    constraint arcs (CVE-2007-4772).

  - Prevent certain PL/Java parameters from being set by
    non-superusers (CVE-2016-0766, boo#966435).

  - Fix many issues in pg_dump with specific object types

  - Prevent over-eager pushdown of HAVING clauses for
    GROUPING SETS

  - Fix deparsing error with ON CONFLICT ... WHERE clauses

  - Fix tableoid errors for postgres_fdw

  - Prevent floating-point exceptions in pgbench

  - Make \det search Foreign Table names consistently

  - Fix quoting of domain constraint names in pg_dump

  - Prevent putting expanded objects into Const nodes

  - Allow compile of PL/Java on Windows

  - Fix 'unresolved symbol' errors in PL/Python execution

  - Allow Python2 and Python3 to be used in the same
    database

  - Add support for Python 3.5 in PL/Python

  - Fix issue with subdirectory creation during initdb

  - Make pg_ctl report status correctly on Windows

  - Suppress confusing error when using pg_receivexlog with
    older servers

  - Multiple documentation corrections and additions

  - Fix erroneous hash calculations in
    gin_extract_jsonb_path()

  - For the full release notse, see:
    http://www.postgresql.org/docs/9.3/static/release-9-3-11
    .html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/9.3/static/release-9-3-11.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966435"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966436"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql93 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-init");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql93");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql93-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql93-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql93-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql93-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql93-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql93-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql93-libs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql93-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql93-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql93-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql93-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql93-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql93-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql93-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql93-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql93-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"libecpg6-9.3.11-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libecpg6-debuginfo-9.3.11-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpq5-9.3.11-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpq5-debuginfo-9.3.11-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-9.3.11-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-contrib-9.3.11-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-contrib-debuginfo-9.3.11-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-debuginfo-9.3.11-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-debugsource-9.3.11-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-devel-9.3.11-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-devel-debuginfo-9.3.11-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-libs-debugsource-9.3.11-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-plperl-9.3.11-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-plperl-debuginfo-9.3.11-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-plpython-9.3.11-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-plpython-debuginfo-9.3.11-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-pltcl-9.3.11-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-pltcl-debuginfo-9.3.11-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-server-9.3.11-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-server-debuginfo-9.3.11-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-test-9.3.11-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libecpg6-32bit-9.3.11-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libecpg6-debuginfo-32bit-9.3.11-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpq5-32bit-9.3.11-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpq5-debuginfo-32bit-9.3.11-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql-init-9.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql93-9.3.11-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql93-contrib-9.3.11-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql93-contrib-debuginfo-9.3.11-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql93-debuginfo-9.3.11-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql93-debugsource-9.3.11-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql93-devel-9.3.11-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql93-devel-debuginfo-9.3.11-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql93-libs-debugsource-9.3.11-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql93-plperl-9.3.11-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql93-plperl-debuginfo-9.3.11-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql93-plpython-9.3.11-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql93-plpython-debuginfo-9.3.11-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql93-pltcl-9.3.11-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql93-pltcl-debuginfo-9.3.11-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql93-server-9.3.11-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql93-server-debuginfo-9.3.11-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql93-test-9.3.11-3.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libecpg6-32bit / libecpg6 / libecpg6-debuginfo-32bit / etc");
}
