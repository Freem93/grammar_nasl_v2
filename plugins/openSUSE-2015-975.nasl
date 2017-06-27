#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-975.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(87715);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2015-8459", "CVE-2015-8460", "CVE-2015-8634", "CVE-2015-8635", "CVE-2015-8636", "CVE-2015-8638", "CVE-2015-8639", "CVE-2015-8640", "CVE-2015-8641", "CVE-2015-8642", "CVE-2015-8643", "CVE-2015-8644", "CVE-2015-8645", "CVE-2015-8646", "CVE-2015-8647", "CVE-2015-8648", "CVE-2015-8649", "CVE-2015-8650", "CVE-2015-8651");

  script_name(english:"openSUSE Security Update : flash-player (openSUSE-2015-975)");
  script_summary(english:"Check for the openSUSE-2015-975 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for flash-player fixes the following issues :

  - Security update to 11.2.202.559 (boo#960317) :

  - APSB16-01, CVE-2015-8459, CVE-2015-8460, CVE-2015-8634,
    CVE-2015-8635, CVE-2015-8636, CVE-2015-8638,
    CVE-2015-8639, CVE-2015-8640, CVE-2015-8641,
    CVE-2015-8642, CVE-2015-8643, CVE-2015-8644,
    CVE-2015-8645, CVE-2015-8646, CVE-2015-8647,
    CVE-2015-8648, CVE-2015-8649, CVE-2015-8650,
    CVE-2015-8651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960317"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected flash-player packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player-kde4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/04");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"flash-player-11.2.202.559-150.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"flash-player-gnome-11.2.202.559-150.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"flash-player-kde4-11.2.202.559-150.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"flash-player-11.2.202.559-2.85.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"flash-player-gnome-11.2.202.559-2.85.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"flash-player-kde4-11.2.202.559-2.85.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "flash-player / flash-player-gnome / flash-player-kde4");
}
