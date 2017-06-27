#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-189.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(81620);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/05/31 04:37:06 $");

  script_cve_id("CVE-2014-8161", "CVE-2015-0241", "CVE-2015-0243", "CVE-2015-0244");

  script_name(english:"openSUSE Security Update : postgresql93 (openSUSE-2015-189)");
  script_summary(english:"Check for the openSUSE-2015-189 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"postgresql93 was updated to version 9.3.6 to fix four security issues.

These security issues were fixed :

  - CVE-2015-0241: Fix buffer overruns in to_char()
    (bnc#916953).

  - CVE-2015-0243: Fix buffer overruns in contrib/pgcrypto
    (bnc#916953).

  - CVE-2015-0244: Fix possible loss of frontend/backend
    protocol synchronization after an error (bnc#916953).

  - CVE-2014-8161: Fix information leak via
    constraint-violation error messages (bnc#916953)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=916953"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql93 packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.2", reference:"libecpg6-9.3.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libecpg6-debuginfo-9.3.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpq5-9.3.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpq5-debuginfo-9.3.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-9.3.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-contrib-9.3.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-contrib-debuginfo-9.3.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-debuginfo-9.3.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-debugsource-9.3.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-devel-9.3.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-devel-debuginfo-9.3.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-libs-debugsource-9.3.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-plperl-9.3.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-plperl-debuginfo-9.3.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-plpython-9.3.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-plpython-debuginfo-9.3.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-pltcl-9.3.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-pltcl-debuginfo-9.3.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-server-9.3.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-server-debuginfo-9.3.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"postgresql93-test-9.3.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libecpg6-32bit-9.3.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libecpg6-debuginfo-32bit-9.3.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpq5-32bit-9.3.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpq5-debuginfo-32bit-9.3.6-2.4.1") ) flag++;

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
