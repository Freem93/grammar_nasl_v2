#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1484.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(95913);
  script_version("$Revision: 3.7 $");
  script_cvs_date("$Date: 2017/01/16 16:05:33 $");

  script_cve_id("CVE-2016-7867", "CVE-2016-7868", "CVE-2016-7869", "CVE-2016-7870", "CVE-2016-7871", "CVE-2016-7872", "CVE-2016-7873", "CVE-2016-7874", "CVE-2016-7875", "CVE-2016-7876", "CVE-2016-7877", "CVE-2016-7878", "CVE-2016-7879", "CVE-2016-7880", "CVE-2016-7881", "CVE-2016-7890", "CVE-2016-7892");

  script_name(english:"openSUSE Security Update : flash-player (openSUSE-2016-1484)");
  script_summary(english:"Check for the openSUSE-2016-1484 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for flash-player fixes the following issues :

  - Security update to 24.0.0.186 (bsc#1015379) APSB16-39 :

  - These updates resolve use-after-free vulnerabilities
    that could have lead to code execution (CVE-2016-7872,
    CVE-2016-7877, CVE-2016-7878, CVE-2016-7879,
    CVE-2016-7880, CVE-2016-7881, CVE-2016-7892).

  - These updates resolve buffer overflow vulnerabilities
    that could have lead to code execution (CVE-2016-7867,
    CVE-2016-7868, CVE-2016-7869, CVE-2016-7870).

  - These updates resolve memory corruption vulnerabilities
    that could have lead to code execution (CVE-2016-7871,
    CVE-2016-7873, CVE-2016-7874, CVE-2016-7875,
    CVE-2016-7876).

  - These updates resolve a security bypass vulnerability
    (CVE-2016-7890).

  - Update EULA to version 24.0."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015379"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.2", reference:"flash-player-24.0.0.186-2.121.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"flash-player-gnome-24.0.0.186-2.121.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"flash-player-kde4-24.0.0.186-2.121.1") ) flag++;

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
