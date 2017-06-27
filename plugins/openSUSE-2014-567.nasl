#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-567.
#
# The text description of this plugin is (C) SUSE LLC.
#

# @DEPRECATED@
#
# This script has been deprecated as it has been determined that the
# advisory was withdrawn and fixed prior to release of openSUSE 13.2.
#
# Disabled on 2015/11/02.
#


include("compat.inc");

if (description)
{
  script_id(78115);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/11/03 20:54:04 $");

  script_cve_id("CVE-2014-6271", "CVE-2014-7169", "CVE-2014-7186", "CVE-2014-7187");
  script_xref(name:"IAVA", value:"2014-A-0142");

  script_name(english:"openSUSE Security Update : bash (openSUSE-SU-2014:1254-1) (deprecated)");
  script_summary(english:"Check for the openSUSE-2014-567 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This patch was withdrawn by the openSUSE team, as the software was
fixed prior to release. No replacement patches/plugins exist.

bash was updated to fix command injection via environment variables.
(CVE-2014-6271,CVE-2014-7169)

Also a hardening patch was applied that only imports functions over
BASH_FUNC_ prefixed environment variables.

Also fixed: CVE-2014-7186, CVE-2014-7187: bad handling of HERE
documents and for loop issue"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-09/msg00063.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=895475"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=896776"
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache mod_cgi Bash Environment Variable Code Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bash-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bash-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bash-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bash-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bash-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bash-loadables");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bash-loadables-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreadline6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreadline6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreadline6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreadline6-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:readline-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:readline-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/10");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}

# Deprecated.
exit(0, "The advisory was withdrawn by the vendor as the patch is not needed.");

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

if ( rpm_check(release:"SUSE13.2", reference:"bash-4.2-75.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bash-debuginfo-4.2-75.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bash-debugsource-4.2-75.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bash-devel-4.2-75.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bash-lang-4.2-75.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bash-loadables-4.2-75.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bash-loadables-debuginfo-4.2-75.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreadline6-6.2-75.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreadline6-debuginfo-6.2-75.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"readline-devel-6.2-75.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"bash-debuginfo-32bit-4.2-75.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libreadline6-32bit-6.2-75.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libreadline6-debuginfo-32bit-6.2-75.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"readline-devel-32bit-6.2-75.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bash");
}
