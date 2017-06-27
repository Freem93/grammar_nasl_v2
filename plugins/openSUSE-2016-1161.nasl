#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1161.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(93997);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/05/19 14:17:02 $");

  script_cve_id("CVE-2016-5423", "CVE-2016-5424");

  script_name(english:"openSUSE Security Update : postgresql94 (openSUSE-2016-1161)");
  script_summary(english:"Check for the openSUSE-2016-1161 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for postgresql94 to version 9.4.9 fixes the several
issues.

These security issues were fixed :

  - CVE-2016-5423: CASE/WHEN with inlining can cause
    untrusted pointer dereference (bsc#993454).

  - CVE-2016-5424: Fix client programs' handling of special
    characters in database and role names (bsc#993453).

This non-security issue was fixed :

  - bsc#973660: Added 'Requires: timezone' to Service Pack

For additional non-security issues please refer to

- http://www.postgresql.org/docs/9.4/static/release-9-4-9.html

- http://www.postgresql.org/docs/9.4/static/release-9-4-8.html

- http://www.postgresql.org/docs/9.4/static/release-9-4-7.html

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/9.4/static/release-9-4-7.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/9.4/static/release-9-4-8.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/9.4/static/release-9-4-9.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=973660"
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
    attribute:"solution", 
    value:"Update the affected postgresql94 packages."
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-libs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql94-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/12");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libecpg6-9.4.9-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libecpg6-debuginfo-9.4.9-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpq5-9.4.9-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpq5-debuginfo-9.4.9-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql94-9.4.9-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql94-contrib-9.4.9-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql94-contrib-debuginfo-9.4.9-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql94-debuginfo-9.4.9-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql94-debugsource-9.4.9-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql94-devel-9.4.9-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql94-devel-debuginfo-9.4.9-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql94-libs-debugsource-9.4.9-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql94-plperl-9.4.9-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql94-plperl-debuginfo-9.4.9-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql94-plpython-9.4.9-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql94-plpython-debuginfo-9.4.9-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql94-pltcl-9.4.9-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql94-pltcl-debuginfo-9.4.9-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql94-server-9.4.9-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql94-server-debuginfo-9.4.9-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"postgresql94-test-9.4.9-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libecpg6-32bit-9.4.9-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libecpg6-debuginfo-32bit-9.4.9-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpq5-32bit-9.4.9-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpq5-debuginfo-32bit-9.4.9-7.1") ) flag++;

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
