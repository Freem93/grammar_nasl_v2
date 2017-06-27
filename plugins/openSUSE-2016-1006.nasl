#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1006.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(93066);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2016-4303");

  script_name(english:"openSUSE Security Update : iperf (openSUSE-2016-1006)");
  script_summary(english:"Check for the openSUSE-2016-1006 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"iperf was updated to the the following vulnerability :

  - CVE-2016-4303: A malicious client could have triggered a
    buffer overflow / heap corruption issue by sending a
    specially crafted JSON string, and possibly execute
    arbitrary code (boo#984453)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984453"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected iperf packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iperf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iperf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iperf-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iperf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libiperf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libiperf0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/22");
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

if ( rpm_check(release:"SUSE13.2", reference:"iperf-3.0.12-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"iperf-debuginfo-3.0.12-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"iperf-debugsource-3.0.12-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"iperf-devel-3.0.12-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libiperf0-3.0.12-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libiperf0-debuginfo-3.0.12-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"iperf-3.0.12-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"iperf-debuginfo-3.0.12-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"iperf-debugsource-3.0.12-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"iperf-devel-3.0.12-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libiperf0-3.0.12-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libiperf0-debuginfo-3.0.12-5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "iperf / iperf-debuginfo / iperf-debugsource / iperf-devel / etc");
}
