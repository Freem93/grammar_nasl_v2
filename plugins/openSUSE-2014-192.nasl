#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-192.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75281);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/18 15:00:16 $");

  script_cve_id("CVE-2014-0060", "CVE-2014-0061", "CVE-2014-0062", "CVE-2014-0063", "CVE-2014-0064", "CVE-2014-0065", "CVE-2014-0066", "CVE-2014-0067");

  script_name(english:"openSUSE Security Update : postgresql92 (openSUSE-SU-2014:0345-1)");
  script_summary(english:"Check for the openSUSE-2014-192 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The PostgreSQL database was updated to the security and bugfix release
9.2.7, which following fixes :

  - Shore up GRANT ... WITH ADMIN OPTION restrictions
    (CVE-2014-0060, bnc#864845)

  - Prevent privilege escalation via manual calls to PL
    validator functions (CVE-2014-0061, bnc#864846)

  - Avoid multiple name lookups during table and index DDL
    (CVE-2014-0062, bnc#864847)

  - Prevent buffer overrun with long datetime strings
    (CVE-2014-0063, bnc#864850)

  - Prevent buffer overrun due to integer overflow in size
    calculations (CVE-2014-0064, bnc#864851)

  - Prevent overruns of fixed-size buffers (CVE-2014-0065,
    bnc#864852)

  - Avoid crashing if crypt() returns NULL (CVE-2014-0066,
    bnc#864853)

  - Document risks of make check in the regression testing
    instructions (CVE-2014-0067)

  - For the other (many!) bug fixes, see the release notes:
    http://www.postgresql.org/docs/9.3/static/release-9-2-7.
    html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-03/msg00018.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/9.3/static/release-9-2-7.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864852"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864853"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql92 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql92");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql92-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql92-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql92-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql92-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql92-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql92-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql92-libs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql92-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql92-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql92-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql92-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql92-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql92-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql92-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql92-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/28");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"libecpg6-9.2.7-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libecpg6-debuginfo-9.2.7-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpq5-9.2.7-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpq5-debuginfo-9.2.7-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"postgresql92-9.2.7-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"postgresql92-contrib-9.2.7-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"postgresql92-contrib-debuginfo-9.2.7-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"postgresql92-debuginfo-9.2.7-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"postgresql92-debugsource-9.2.7-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"postgresql92-devel-9.2.7-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"postgresql92-devel-debuginfo-9.2.7-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"postgresql92-libs-debugsource-9.2.7-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"postgresql92-plperl-9.2.7-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"postgresql92-plperl-debuginfo-9.2.7-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"postgresql92-plpython-9.2.7-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"postgresql92-plpython-debuginfo-9.2.7-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"postgresql92-pltcl-9.2.7-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"postgresql92-pltcl-debuginfo-9.2.7-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"postgresql92-server-9.2.7-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"postgresql92-server-debuginfo-9.2.7-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libecpg6-32bit-9.2.7-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libecpg6-debuginfo-32bit-9.2.7-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libpq5-32bit-9.2.7-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libpq5-debuginfo-32bit-9.2.7-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libecpg6-9.2.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libecpg6-debuginfo-9.2.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpq5-9.2.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpq5-debuginfo-9.2.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-9.2.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-contrib-9.2.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-contrib-debuginfo-9.2.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-debuginfo-9.2.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-debugsource-9.2.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-devel-9.2.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-devel-debuginfo-9.2.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-libs-debugsource-9.2.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-plperl-9.2.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-plperl-debuginfo-9.2.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-plpython-9.2.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-plpython-debuginfo-9.2.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-pltcl-9.2.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-pltcl-debuginfo-9.2.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-server-9.2.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-server-debuginfo-9.2.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libecpg6-32bit-9.2.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libecpg6-debuginfo-32bit-9.2.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpq5-32bit-9.2.7-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpq5-debuginfo-32bit-9.2.7-4.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql92");
}
