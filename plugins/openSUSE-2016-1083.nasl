#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1083.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(93553);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2016-4182", "CVE-2016-4237", "CVE-2016-4238", "CVE-2016-4271", "CVE-2016-4272", "CVE-2016-4274", "CVE-2016-4275", "CVE-2016-4276", "CVE-2016-4277", "CVE-2016-4278", "CVE-2016-4279", "CVE-2016-4280", "CVE-2016-4281", "CVE-2016-4282", "CVE-2016-4283", "CVE-2016-4284", "CVE-2016-4285", "CVE-2016-4287", "CVE-2016-6921", "CVE-2016-6922", "CVE-2016-6923", "CVE-2016-6924", "CVE-2016-6925", "CVE-2016-6926", "CVE-2016-6927", "CVE-2016-6929", "CVE-2016-6930", "CVE-2016-6931", "CVE-2016-6932");

  script_name(english:"openSUSE Security Update : flash-player (openSUSE-2016-1083)");
  script_summary(english:"Check for the openSUSE-2016-1083 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for flash-player fixes the following security issues
(APSB16-29, boo#998589) :

  - integer overflow vulnerability that could lead to code
    execution (CVE-2016-4287). 

  - use-after-free vulnerabilities that could lead to code
    execution (CVE-2016-4272, CVE-2016-4279, CVE-2016-6921,
    CVE-2016-6923, CVE-2016-6925, CVE-2016-6926,
    CVE-2016-6927, CVE-2016-6929, CVE-2016-6930,
    CVE-2016-6931, CVE-2016-6932)

  - security bypass vulnerabilities that could lead to
    information disclosure (CVE-2016-4271, CVE-2016-4277,
    CVE-2016-4278)

  - memory corruption vulnerabilities that could lead to
    code execution (CVE-2016-4182, CVE-2016-4237,
    CVE-2016-4238, CVE-2016-4274, CVE-2016-4275,
    CVE-2016-4276, CVE-2016-4280, CVE-2016-4281,
    CVE-2016-4282, CVE-2016-4283, CVE-2016-4284,
    CVE-2016-4285, CVE-2016-6922, CVE-2016-6924)

The package description was update to reflex that the stand-alone
Flash is no longer provided on x86_64 architectures (boo#977664)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977664"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=998589"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected flash-player packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player-kde4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/16");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"flash-player-11.2.202.635-2.108.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"flash-player-gnome-11.2.202.635-2.108.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"flash-player-kde4-11.2.202.635-2.108.1") ) flag++;

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
