#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-559.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(77846);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/12/03 05:40:30 $");

  script_cve_id("CVE-2014-2524", "CVE-2014-6271");
  script_xref(name:"IAVA", value:"2014-A-0142");

  script_name(english:"openSUSE Security Update : bash (openSUSE-SU-2014:1226-1) (Shellshock)");
  script_summary(english:"Check for the openSUSE-2014-559 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"bash was updated to fix a critical security issue, a minor security
issue and bugs :

In some circumstances, the shell would evaluate shellcode in
environment variables passed at startup time. This allowed code
execution by local or remote attackers who could pass environment
variables to bash scripts. (CVE-2014-6271)

Fixed a temporary file misuse in _rl_tropen (bnc#868822) Even if used
only by developers to debug readline library do not open temporary
files from public location without O_EXCL (CVE-2014-2524)

Additional bugfixes :

  - Backported corrected german error message for a failing
    getpwd (bnc#895475)

  - Add bash upstream patch 47 to fix a problem where the
    function that shortens pathnames for $PS1 according to
    the value of $PROMPT_DIRTRIM uses memcpy on
    potentially-overlapping regions of memory, when it
    should use memmove. The result is garbled pathnames in
    prompt strings.

  - Add bash upstream patch 46 to fix a problem introduced
    by patch 32 a problem with '$@' and arrays expanding
    empty positional parameters or array elements when using
    substring expansion, pattern substitution, or case
    modfication. The empty parameters or array elements are
    removed instead of expanding to empty strings ('').

  - Add bash-4.2-strcpy.patch from upstream mailing list to
    patch collection tar ball to avoid when using \w in the
    prompt and changing the directory outside of HOME the a
    strcpy work on overlapping memory areas."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-09/msg00036.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=868822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=895475"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=896776"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bash packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/25");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if ( rpm_check(release:"SUSE12.3", reference:"bash-4.2-61.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"bash-debuginfo-4.2-61.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"bash-debugsource-4.2-61.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"bash-devel-4.2-61.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"bash-lang-4.2-61.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"bash-loadables-4.2-61.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"bash-loadables-debuginfo-4.2-61.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libreadline6-6.2-61.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libreadline6-debuginfo-6.2-61.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"readline-devel-6.2-61.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"bash-debuginfo-32bit-4.2-61.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libreadline6-32bit-6.2-61.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libreadline6-debuginfo-32bit-6.2-61.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"readline-devel-32bit-6.2-61.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bash-4.2-68.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bash-debuginfo-4.2-68.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bash-debugsource-4.2-68.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bash-devel-4.2-68.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bash-lang-4.2-68.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bash-loadables-4.2-68.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bash-loadables-debuginfo-4.2-68.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreadline6-6.2-68.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreadline6-debuginfo-6.2-68.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"readline-devel-6.2-68.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"bash-debuginfo-32bit-4.2-68.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libreadline6-32bit-6.2-68.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libreadline6-debuginfo-32bit-6.2-68.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"readline-devel-32bit-6.2-68.4.1") ) flag++;

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
