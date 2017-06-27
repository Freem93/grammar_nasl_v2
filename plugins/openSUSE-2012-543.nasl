#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-543.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74735);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2012-2763", "CVE-2012-3236", "CVE-2012-3403", "CVE-2012-3481");
  script_osvdb_id(82429, 83634, 84830, 84831);

  script_name(english:"openSUSE Security Update : gimp (openSUSE-SU-2012:1080-1)");
  script_summary(english:"Check for the openSUSE-2012-543 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple integer overflows in various decoder plug-ins of GIMP have
been fixed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-09/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=724628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=763595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=769565"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=775433"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gimp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'GIMP script-fu Server Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-help-browser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-help-browser-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-module-hal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-module-hal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-plugins-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-plugins-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimp-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimp-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimp-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimp-2_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimpui-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimpui-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimpui-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimpui-2_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/27");
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
if (release !~ "^(SUSE11\.4|SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4 / 12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"gimp-2.6.11-13.58.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"gimp-branding-upstream-2.6.11-13.58.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"gimp-debuginfo-2.6.11-13.58.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"gimp-debugsource-2.6.11-13.58.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"gimp-devel-2.6.11-13.58.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"gimp-devel-debuginfo-2.6.11-13.58.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"gimp-help-browser-2.6.11-13.58.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"gimp-help-browser-debuginfo-2.6.11-13.58.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"gimp-lang-2.6.11-13.58.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"gimp-module-hal-2.6.11-13.58.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"gimp-module-hal-debuginfo-2.6.11-13.58.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"gimp-plugins-python-2.6.11-13.58.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"gimp-plugins-python-debuginfo-2.6.11-13.58.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libgimp-2_0-0-2.6.11-13.58.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libgimp-2_0-0-debuginfo-2.6.11-13.58.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libgimpui-2_0-0-2.6.11-13.58.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libgimpui-2_0-0-debuginfo-2.6.11-13.58.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libgimp-2_0-0-32bit-2.6.11-13.58.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libgimp-2_0-0-debuginfo-32bit-2.6.11-13.58.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libgimpui-2_0-0-32bit-2.6.11-13.58.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libgimpui-2_0-0-debuginfo-32bit-2.6.11-13.58.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"gimp-2.6.11-28.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"gimp-branding-upstream-2.6.11-28.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"gimp-debuginfo-2.6.11-28.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"gimp-debugsource-2.6.11-28.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"gimp-devel-2.6.11-28.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"gimp-devel-debuginfo-2.6.11-28.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"gimp-help-browser-2.6.11-28.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"gimp-help-browser-debuginfo-2.6.11-28.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"gimp-lang-2.6.11-28.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"gimp-plugins-python-2.6.11-28.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"gimp-plugins-python-debuginfo-2.6.11-28.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libgimp-2_0-0-2.6.11-28.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libgimp-2_0-0-debuginfo-2.6.11-28.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libgimpui-2_0-0-2.6.11-28.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libgimpui-2_0-0-debuginfo-2.6.11-28.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libgimp-2_0-0-32bit-2.6.11-28.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libgimp-2_0-0-debuginfo-32bit-2.6.11-28.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libgimpui-2_0-0-32bit-2.6.11-28.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libgimpui-2_0-0-debuginfo-32bit-2.6.11-28.26.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gimp");
}
