#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-535.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(77621);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/11/16 15:47:33 $");

  script_cve_id("CVE-2014-0547", "CVE-2014-0548", "CVE-2014-0549", "CVE-2014-0550", "CVE-2014-0551", "CVE-2014-0552", "CVE-2014-0553", "CVE-2014-0554", "CVE-2014-0555", "CVE-2014-0556", "CVE-2014-0557", "CVE-2014-0559");

  script_name(english:"openSUSE Security Update : flash-player (openSUSE-SU-2014:1110-1)");
  script_summary(english:"Check for the openSUSE-2014-535 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Adobe Flash Player was updated to 11.2.202.406 (bnc#895856) :

  - APSB14-21, CVE-2014-0547, CVE-2014-0548, CVE-2014-0549,
    CVE-2014-0550, CVE-2014-0551, CVE-2014-0552,
    CVE-2014-0553, CVE-2014-0554, CVE-2014-0555,
    CVE-2014-0556, CVE-2014-0557, CVE-2014-0559

More information can be found on :

http://helpx.adobe.com/security/products/flash-player/apsb14-21.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://helpx.adobe.com/security/products/flash-player/apsb14-21.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-09/msg00015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=895856"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected flash-player packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player copyPixelsToByteArray Method Integer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player-kde4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/11");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"flash-player-11.2.202.406-2.92.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"flash-player-gnome-11.2.202.406-2.92.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"flash-player-kde4-11.2.202.406-2.92.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"flash-player-11.2.202.406-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"flash-player-gnome-11.2.202.406-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"flash-player-kde4-11.2.202.406-66.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "flash-player");
}
