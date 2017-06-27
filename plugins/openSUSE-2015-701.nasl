#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-701.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86736);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/02/21 05:39:26 $");

  script_cve_id("CVE-2015-5288", "CVE-2015-5289");

  script_name(english:"openSUSE Security Update : postgresql93 (openSUSE-2015-701)");
  script_summary(english:"Check for the openSUSE-2015-701 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"postgresql93 was updated to version 9.3.10 to fix two security issues.

These security issues were fixed :

  - CVE-2015-5288: Unchecked JSON input can crash the server
    (bsc#949669).

  - CVE-2015-5289: Memory leak in crypt() function
    (bsc#949670).

For the full release notes, please see:
http://www.postgresql.org/docs/current/static/release-9-3-10.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/current/static/release-9-3-10.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=949669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=949670"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql93 packages."
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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/05");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"libecpg6-9.3.10-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libecpg6-debuginfo-9.3.10-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpq5-9.3.10-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpq5-debuginfo-9.3.10-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-9.3.10-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-contrib-9.3.10-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-contrib-debuginfo-9.3.10-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-debuginfo-9.3.10-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-debugsource-9.3.10-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-devel-9.3.10-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-devel-debuginfo-9.3.10-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-libs-debugsource-9.3.10-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-plperl-9.3.10-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-plperl-debuginfo-9.3.10-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-plpython-9.3.10-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-plpython-debuginfo-9.3.10-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-pltcl-9.3.10-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-pltcl-debuginfo-9.3.10-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-server-9.3.10-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-server-debuginfo-9.3.10-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-test-9.3.10-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libecpg6-32bit-9.3.10-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libecpg6-debuginfo-32bit-9.3.10-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpq5-32bit-9.3.10-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpq5-debuginfo-32bit-9.3.10-2.7.1") ) flag++;

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
