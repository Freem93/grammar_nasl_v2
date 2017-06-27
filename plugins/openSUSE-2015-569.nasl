#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-569.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(85838);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/09/08 14:15:24 $");

  script_name(english:"openSUSE Security Update : tor (openSUSE-2015-569)");
  script_summary(english:"Check for the openSUSE-2015-569 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tor was updated to fix one logging privacy issue.

The following issue was fixed :

  - Malformed hostnames in socks5 requests were written to
    the log regardless of SafeLogging option (CWE-532)
    [boo#943362]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=943362"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected tor packages.");
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tor-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/08");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"tor-0.2.4.27-5.33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"tor-debuginfo-0.2.4.27-5.33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"tor-debugsource-0.2.4.27-5.33.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"tor-0.2.4.27-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"tor-debuginfo-0.2.4.27-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"tor-debugsource-0.2.4.27-16.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tor / tor-debuginfo / tor-debugsource");
}
