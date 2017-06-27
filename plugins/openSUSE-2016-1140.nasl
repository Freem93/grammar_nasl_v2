#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1140.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(93825);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/05/19 14:17:02 $");

  script_cve_id("CVE-2016-5423", "CVE-2016-5424");

  script_name(english:"openSUSE Security Update : postgresql93 (openSUSE-2016-1140)");
  script_summary(english:"Check for the openSUSE-2016-1140 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The postgresql server postgresql93 was updated to 9.3.14 fixes the
following issues :

Update to version 9.3.14 :

  - Fix possible mis-evaluation of nested CASE-WHEN
    expressions (CVE-2016-5423, boo#993454)

  - Fix client programs' handling of special characters in
    database and role names (CVE-2016-5424, boo#993453)

  - Fix corner-case misbehaviors for IS NULL/IS NOT NULL
    applied to nested composite values

  - Make the inet and cidr data types properly reject IPv6
    addresses with too many colon-separated fields

  - Prevent crash in close_ps() (the point ## lseg operator)
    for NaN input coordinates

  - Fix several one-byte buffer over-reads in to_number()

  - Avoid unsafe intermediate state during expensive paths
    through heap_update()

  - For the other bug fixes, see the release notes:
    https://www.postgresql.org/docs/9.3/static/release-9-3-1
    4.html

Update to version 9.3.13 :

This update fixes several problems which caused downtime for users,
including :

  - Clearing the OpenSSL error queue before OpenSSL calls,
    preventing errors in SSL connections, particularly when
    using the Python, Ruby or PHP OpenSSL wrappers

  - Fixed the 'failed to build N-way joins' planner error

  - Fixed incorrect handling of equivalence in multilevel
    nestloop query plans, which could emit rows which didn't
    match the WHERE clause.

  - Prevented two memory leaks with using GIN indexes,
    including a potential index corruption risk. The release
    also includes many other bug fixes for reported issues,
    many of which affect all supported versions :

  - Fix corner-case parser failures occurring when
    operator_precedence_warning is turned on

  - Prevent possible misbehavior of TH, th, and Y,YYY format
    codes in to_timestamp()

  - Correct dumping of VIEWs and RULEs which use ANY (array)
    in a subselect

  - Disallow newlines in ALTER SYSTEM parameter values

  - Avoid possible misbehavior after failing to remove a
    tablespace symlink

  - Fix crash in logical decoding on alignment-picky
    platforms

  - Avoid repeated requests for feedback from receiver while
    shutting down walsender

  - Multiple fixes for pg_upgrade

  - Support building with Visual Studio 2015

  - This update also contains tzdata release 2016d, with
    updates for Russia, Venezuela, Kirov, and Tomsk.
    http://www.postgresql.org/docs/current/static/release-9-
    3-13.html

Update to version 9.3.12 :

  - Fix two bugs in indexed ROW() comparisons

  - Avoid data loss due to renaming files

  - Prevent an error in rechecking rows in SELECT FOR
    UPDATE/SHARE

  - Fix bugs in multiple json_ and jsonb_ functions

  - Log lock waits for INSERT ON CONFLICT correctly

  - Ignore recovery_min_apply_delay until reaching a
    consistent state

  - Fix issue with pg_subtrans XID wraparound

  - Fix assorted bugs in Logical Decoding

  - Fix planner error with nested security barrier views

  - Prevent memory leak in GIN indexes

  - Fix two issues with ispell dictionaries

  - Avoid a crash on old Windows versions

  - Skip creating an erroneous delete script in pg_upgrade

  - Correctly translate empty arrays into PL/Perl

  - Make PL/Python cope with identifier names

For the full release notes, see:
http://www.postgresql.org/docs/9.4/static/release-9-3-12.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/9.4/static/release-9-3-12.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/current/static/release-9-3-13.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=993453"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=993454"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/9.3/static/release-9-3-14.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql93 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-debuginfo-32bit");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"libecpg6-9.3.14-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libecpg6-debuginfo-9.3.14-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpq5-9.3.14-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpq5-debuginfo-9.3.14-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-9.3.14-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-contrib-9.3.14-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-contrib-debuginfo-9.3.14-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-debuginfo-9.3.14-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-debugsource-9.3.14-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-devel-9.3.14-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-devel-debuginfo-9.3.14-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-libs-debugsource-9.3.14-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-plperl-9.3.14-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-plperl-debuginfo-9.3.14-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-plpython-9.3.14-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-plpython-debuginfo-9.3.14-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-pltcl-9.3.14-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-pltcl-debuginfo-9.3.14-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-server-9.3.14-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-server-debuginfo-9.3.14-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-test-9.3.14-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libecpg6-32bit-9.3.14-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libecpg6-debuginfo-32bit-9.3.14-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpq5-32bit-9.3.14-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpq5-debuginfo-32bit-9.3.14-2.13.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libecpg6-32bit / libecpg6 / libecpg6-debuginfo-32bit / etc");
}
