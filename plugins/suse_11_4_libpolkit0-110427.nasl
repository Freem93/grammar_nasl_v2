#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libpolkit0-4439.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75915);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/10/20 00:03:34 $");

  script_cve_id("CVE-2011-1485");
  script_osvdb_id(72261);

  script_name(english:"openSUSE Security Update : libpolkit0 (openSUSE-SU-2011:0413-1)");
  script_summary(english:"Check for the libpolkit0-4439 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A race condition exists in pkexec while trying to determine its caller
which could lead to privilege escalation. CVE-2011-1485 has been
assigned to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-04/msg00081.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=638784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=688788"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libpolkit0 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux PolicyKit Race Condition Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpolkit0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpolkit0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpolkit0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpolkit0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:polkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:polkit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:polkit-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:polkit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:polkit-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/27");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"libpolkit0-0.99-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libpolkit0-debuginfo-0.99-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"polkit-0.99-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"polkit-debuginfo-0.99-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"polkit-debugsource-0.99-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"polkit-devel-0.99-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"polkit-devel-debuginfo-0.99-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libpolkit0-32bit-0.99-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libpolkit0-debuginfo-32bit-0.99-5.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "polkit");
}
