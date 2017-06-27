#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-314.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(89812);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/03/10 15:12:11 $");

  script_cve_id("CVE-2016-1544");

  script_name(english:"openSUSE Security Update : nghttp2 (openSUSE-2016-314)");
  script_summary(english:"Check for the openSUSE-2016-314 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for nghttp2 fixes the following vulnerabilities :

  - CVE-2016-1544: A malicious remote attacker could have
    caused an Out of memory condition due to unlimited
    incoming HTTP header fields (boo#966514)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966514"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nghttp2 packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnghttp2-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnghttp2-14-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnghttp2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnghttp2_asio-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnghttp2_asio1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnghttp2_asio1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nghttp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nghttp2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nghttp2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-nghttp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-nghttp2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/10");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libnghttp2-14-1.3.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libnghttp2-14-debuginfo-1.3.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libnghttp2-devel-1.3.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libnghttp2_asio-devel-1.3.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libnghttp2_asio1-1.3.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libnghttp2_asio1-debuginfo-1.3.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nghttp2-1.3.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nghttp2-debuginfo-1.3.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nghttp2-debugsource-1.3.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python-nghttp2-1.3.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python-nghttp2-debuginfo-1.3.4-3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libnghttp2-14 / libnghttp2-14-debuginfo / libnghttp2-devel / etc");
}
