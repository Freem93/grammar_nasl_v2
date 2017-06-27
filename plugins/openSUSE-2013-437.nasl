#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-437.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75008);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/09 15:44:47 $");

  script_cve_id("CVE-2013-2549", "CVE-2013-2550", "CVE-2013-2718", "CVE-2013-2719", "CVE-2013-2720", "CVE-2013-2721", "CVE-2013-2722", "CVE-2013-2723", "CVE-2013-2724", "CVE-2013-2725", "CVE-2013-2726", "CVE-2013-2727", "CVE-2013-2729", "CVE-2013-2730", "CVE-2013-2731", "CVE-2013-2732", "CVE-2013-2733", "CVE-2013-2734", "CVE-2013-2735", "CVE-2013-2736", "CVE-2013-2737", "CVE-2013-3337", "CVE-2013-3338", "CVE-2013-3339", "CVE-2013-3340", "CVE-2013-3341", "CVE-2013-3342");
  script_bugtraq_id(58398, 58568, 59902, 59903, 59904, 59905, 59906, 59907, 59908, 59909, 59910, 59911, 59912, 59913, 59914, 59915, 59916, 59917, 59918, 59919, 59920, 59921, 59923, 59925, 59926, 59927, 59930);
  script_osvdb_id(91201, 91202, 93335, 93336, 93337, 93338, 93339, 93340, 93341, 93342, 93343, 93344, 93345, 93346, 93347, 93348, 93349, 93350, 93351, 93352, 93353, 93354, 93355, 93356, 93357, 93358, 93359);

  script_name(english:"openSUSE Security Update : acroread (openSUSE-SU-2013:0990-1)");
  script_summary(english:"Check for the openSUSE-2013-437 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Acroread was updated to 9.5.5 for bnc#819918(swampid#52449).

More information can be found on:
https://www.adobe.com/support/security/bulletins/apsb13-15.html

(CVE-2013-2549, CVE-2013-2550, CVE-2013-2718, CVE-2013-2719,
CVE-2013-2720, CVE-2013-2721, CVE-2013-2722, CVE-2013-2723,
CVE-2013-2724, CVE-2013-2725, CVE-2013-2726, CVE-2013-2727,
CVE-2013-2729, CVE-2013-2730, CVE-2013-2731, CVE-2013-2732,
CVE-2013-2733, CVE-2013-2734, CVE-2013-2735, CVE-2013-2736,
CVE-2013-2737, CVE-2013-3337, CVE-2013-3338, CVE-2013-3339,
CVE-2013-3340, CVE-2013-3341, CVE-2013-3342)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-06/msg00126.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819918"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.adobe.com/support/security/bulletins/apsb13-15.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected acroread packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'AdobeCollabSync Buffer Overflow Adobe Reader X Sandbox Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread-browser-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread-cmaps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread-fonts-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread-fonts-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread-fonts-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread-fonts-zh_TW");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686)$") audit(AUDIT_ARCH_NOT, "i586 / i686", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"acroread-9.5.5-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"acroread-browser-plugin-9.5.5-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"acroread-cmaps-9.4.1-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"acroread-fonts-ja-9.4.1-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"acroread-fonts-ko-9.4.1-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"acroread-fonts-zh_CN-9.4.1-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"acroread-fonts-zh_TW-9.4.1-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"acroread-9.5.5-4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"acroread-browser-plugin-9.5.5-4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"acroread-cmaps-9.4.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"acroread-fonts-ja-9.4.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"acroread-fonts-ko-9.4.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"acroread-fonts-zh_CN-9.4.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"acroread-fonts-zh_TW-9.4.1-4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "acroread");
}
