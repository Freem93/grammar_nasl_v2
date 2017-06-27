#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1172.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(94002);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/14 13:45:02 $");

  script_cve_id("CVE-2016-1669", "CVE-2016-2178", "CVE-2016-2183", "CVE-2016-5325", "CVE-2016-6304", "CVE-2016-6306", "CVE-2016-7052", "CVE-2016-7099");

  script_name(english:"openSUSE Security Update : nodejs (openSUSE-2016-1172)");
  script_summary(english:"Check for the openSUSE-2016-1172 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings the new upstream nodejs LTS version 4.6.0, fixing
bugs and security issues :

  - Nodejs embedded openssl version update

  + upgrade to 1.0.2j (CVE-2016-6304, CVE-2016-2183,
    CVE-2016-2178, CVE-2016-6306, CVE-2016-7052)

  + remove support for dynamic 3rd party engine modules

- http: Properly validate for allowable characters in input
user data. This introduces a new case where throw may occur
when configuring HTTP responses, users should already
be adopting try/catch here.
  (CVE-2016-5325, bsc#985201)

  - tls: properly validate wildcard certificates
    (CVE-2016-7099, bsc#1001652)

  - buffer: Zero-fill excess bytes in new Buffer objects
    created with Buffer.concat()"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1001652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985201"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nodejs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:npm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/12");
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

if ( rpm_check(release:"SUSE13.2", reference:"nodejs-4.6.0-24.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"nodejs-debuginfo-4.6.0-24.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"nodejs-debugsource-4.6.0-24.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"nodejs-devel-4.6.0-24.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nodejs-4.6.0-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nodejs-debuginfo-4.6.0-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nodejs-debugsource-4.6.0-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nodejs-devel-4.6.0-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"npm-4.6.0-33.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nodejs / nodejs-debuginfo / nodejs-debugsource / nodejs-devel / npm");
}
