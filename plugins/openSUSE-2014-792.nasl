#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-792.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(80151);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/11/01 04:40:11 $");

  script_cve_id("CVE-2014-9295", "CVE-2014-9296");

  script_name(english:"openSUSE Security Update : ntp (openSUSE-SU-2014:1670-1)");
  script_summary(english:"Check for the openSUSE-2014-792 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The network timeservice ntp was updated to fix critical security
issues (bnc#910764, CERT VU#852879)

  - A potential remote code execution problem was found
    inside ntpd. The functions crypto_recv() (when using
    autokey authentication), ctl_putdata(), and configure()
    where updated to avoid buffer overflows that could be
    exploited. (CVE-2014-9295)

  - Furthermore a problem inside the ntpd error handling was
    found that is missing a return statement. This could
    also lead to a potentially attack vector.
    (CVE-2014-9296)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-12/msg00075.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=910764"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ntp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntp-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/22");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"ntp-4.2.6p5-9.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ntp-debuginfo-4.2.6p5-9.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ntp-debugsource-4.2.6p5-9.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ntp-4.2.6p5-15.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ntp-debuginfo-4.2.6p5-15.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ntp-debugsource-4.2.6p5-15.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ntp-4.2.6p5-25.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ntp-debuginfo-4.2.6p5-25.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ntp-debugsource-4.2.6p5-25.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp / ntp-debuginfo / ntp-debugsource");
}
