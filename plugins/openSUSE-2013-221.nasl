#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-221.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74928);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2013-1775", "CVE-2013-1776");

  script_name(english:"openSUSE Security Update : sudo (openSUSE-SU-2013:0495-1)");
  script_summary(english:"Check for the openSUSE-2013-221 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"sudo was updated to fix two security issues, where adjusting the time
of the syste could be used to regain access to sudo sessions if they
onc were granted. (CVE-2013-1775,CVE-2013-1776)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-03/msg00066.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806921"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sudo packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mac OS X Sudo Password Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sudo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sudo-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sudo-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"sudo-1.8.2-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"sudo-debuginfo-1.8.2-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"sudo-debugsource-1.8.2-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"sudo-devel-1.8.2-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"sudo-1.8.5p2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"sudo-debuginfo-1.8.5p2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"sudo-debugsource-1.8.5p2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"sudo-devel-1.8.5p2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"sudo-1.8.6p3-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"sudo-debuginfo-1.8.6p3-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"sudo-debugsource-1.8.6p3-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"sudo-devel-1.8.6p3-3.5.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sudo");
}
