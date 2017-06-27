#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-708.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86777);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/02/21 05:39:26 $");

  script_cve_id("CVE-2015-5288");

  script_name(english:"openSUSE Security Update : postgresql92 (openSUSE-2015-708)");
  script_summary(english:"Check for the openSUSE-2015-708 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"postgresql92 was updated to version 9.2.14 to fix one security issue.

This security issue was fixed :

  - CVE-2015-5288: The crypt function in contrib/pgcrypto in
    PostgreSQL before 9.0.23, 9.1.x before 9.1.19, 9.2.x
    before 9.2.14, 9.3.x before 9.3.10, and 9.4.x before
    9.4.5 allowed attackers to cause a denial of service
    (server crash) or read arbitrary server memory via a
    'too-short' salt (bsc#949669).

For the full release notes see:
http://www.postgresql.org/docs/current/static/release-9-2-14.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/current/static/release-9-2-14.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=949669"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql92 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.1", reference:"libecpg6-9.2.14-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libecpg6-debuginfo-9.2.14-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpq5-9.2.14-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpq5-debuginfo-9.2.14-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-9.2.14-4.7.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-contrib-9.2.14-4.7.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-contrib-debuginfo-9.2.14-4.7.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-debuginfo-9.2.14-4.7.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-debugsource-9.2.14-4.7.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-devel-9.2.14-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-devel-debuginfo-9.2.14-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-libs-debugsource-9.2.14-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-plperl-9.2.14-4.7.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-plperl-debuginfo-9.2.14-4.7.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-plpython-9.2.14-4.7.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-plpython-debuginfo-9.2.14-4.7.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-pltcl-9.2.14-4.7.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-pltcl-debuginfo-9.2.14-4.7.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-server-9.2.14-4.7.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"postgresql92-server-debuginfo-9.2.14-4.7.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libecpg6-32bit-9.2.14-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libecpg6-debuginfo-32bit-9.2.14-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpq5-32bit-9.2.14-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpq5-debuginfo-32bit-9.2.14-4.7.1") ) flag++;

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
