#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-546.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(85435);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/09/23 13:29:16 $");

  script_cve_id("CVE-2015-3107", "CVE-2015-5124", "CVE-2015-5125", "CVE-2015-5127", "CVE-2015-5128", "CVE-2015-5129", "CVE-2015-5130", "CVE-2015-5131", "CVE-2015-5132", "CVE-2015-5133", "CVE-2015-5134", "CVE-2015-5539", "CVE-2015-5540", "CVE-2015-5541", "CVE-2015-5544", "CVE-2015-5545", "CVE-2015-5546", "CVE-2015-5547", "CVE-2015-5548", "CVE-2015-5549", "CVE-2015-5550", "CVE-2015-5551", "CVE-2015-5552", "CVE-2015-5553", "CVE-2015-5554", "CVE-2015-5555", "CVE-2015-5556", "CVE-2015-5557", "CVE-2015-5558", "CVE-2015-5559", "CVE-2015-5560", "CVE-2015-5561", "CVE-2015-5562", "CVE-2015-5563");

  script_name(english:"openSUSE Security Update : flash-player (openSUSE-2015-546)");
  script_summary(english:"Check for the openSUSE-2015-546 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Security update to 11.2.202.508 (bsc#941239) :

  - APSB15-19: CVE-2015-3107, CVE-2015-5124, CVE-2015-5125,
    CVE-2015-5127, CVE-2015-5128, CVE-2015-5129,
    CVE-2015-5130, CVE-2015-5131, CVE-2015-5132,
    CVE-2015-5133, CVE-2015-5134, CVE-2015-5539,
    CVE-2015-5540, CVE-2015-5541, CVE-2015-5544,
    CVE-2015-5545, CVE-2015-5546, CVE-2015-5547,
    CVE-2015-5548, CVE-2015-5549, CVE-2015-5550,
    CVE-2015-5551, CVE-2015-5552, CVE-2015-5553,
    CVE-2015-5554, CVE-2015-5555, CVE-2015-5556,
    CVE-2015-5557, CVE-2015-5558, CVE-2015-5559,
    CVE-2015-5560, CVE-2015-5561, CVE-2015-5562,
    CVE-2015-5563"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=941239"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected flash-player packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player-kde4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/17");
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

if ( rpm_check(release:"SUSE13.2", reference:"flash-player-11.2.202.508-2.67.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"flash-player-gnome-11.2.202.508-2.67.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"flash-player-kde4-11.2.202.508-2.67.1") ) flag++;

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
