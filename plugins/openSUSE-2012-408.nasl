#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-408.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74685);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2012-3410");

  script_name(english:"openSUSE Security Update : bash (openSUSE-SU-2012:0898-1)");
  script_summary(english:"Check for the openSUSE-2012-408 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Bash was fixed to avoid a possible buffer overflow when expanding the
/dev/fd prefix with e.g. the test builtin (bnc#770795) (CVE-2012-3410)

Due to _FORTIFY_SOURCE=2 enablement, the exploit will only abort the
shell."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-07/msg00038.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=770795"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bash packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/12");
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

if ( rpm_check(release:"SUSE11.4", reference:"bash-4.1-20.28.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"bash-debuginfo-4.1-20.28.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"bash-debugsource-4.1-20.28.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"bash-devel-4.1-18.28.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"bash-lang-4.1-20.28.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"bash-loadables-4.1-18.28.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"bash-loadables-debuginfo-4.1-18.28.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreadline6-6.1-18.28.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libreadline6-debuginfo-6.1-18.28.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"readline-devel-6.1-18.28.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"bash-debuginfo-32bit-4.1-20.28.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libreadline6-32bit-6.1-18.28.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libreadline6-debuginfo-32bit-6.1-18.28.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"readline-devel-32bit-6.1-18.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"bash-4.2-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"bash-debuginfo-4.2-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"bash-debugsource-4.2-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"bash-devel-4.2-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"bash-lang-4.2-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"bash-loadables-4.2-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"bash-loadables-debuginfo-4.2-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libreadline6-6.2-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libreadline6-debuginfo-6.2-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"readline-devel-6.2-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"bash-debuginfo-32bit-4.2-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libreadline6-32bit-6.2-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libreadline6-debuginfo-32bit-6.2-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"readline-devel-32bit-6.2-1.14.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bash");
}
