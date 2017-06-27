#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-711.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86957);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/11/20 15:06:53 $");

  script_cve_id("CVE-2015-3218", "CVE-2015-3255", "CVE-2015-3256", "CVE-2015-4625");

  script_name(english:"openSUSE Security Update : polkit (openSUSE-2015-711)");
  script_summary(english:"Check for the openSUSE-2015-711 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"polkit was updated to the 0.113 release, fixing security issues and
bugs.

Security issues fixed :

  - Fixes CVE-2015-4625, a local privilege escalation due to
    predictable authentication session cookie values. Thanks
    to Tavis Ormandy, Google Project Zero for reporting this
    issue. For the future, authentication agents are
    encouraged to use PolkitAgentSession instead of using
    the D-Bus agent response API directly. (bsc#935119)

  - Fixes CVE-2015-3256, various memory corruption
    vulnerabilities in use of the JavaScript interpreter,
    possibly leading to local privilege escalation.
    (bsc#943816)

  - Fixes CVE-2015-3255, a memory corruption vulnerability
    in handling duplicate action IDs, possibly leading to
    local privilege escalation. Thanks to Laurent Bigonville
    for reporting this issue. (bsc#939246)

  - Fixes CVE-2015-3218, which allowed any local user to
    crash polkitd. Thanks to Tavis Ormandy, Google Project
    Zero, for reporting this issue. (bsc#933922)

Other issues fixed :

  - On systemd-213 and later, the 'active' state is shared
    across all sessions of an user, instead of being tracked
    separately.

  - pkexec, when not given a program to execute, runs the
    users shell by default.

  - Fixed shutdown problems on powerpc64le (bsc#950114)

  - polkit had a memory leak (bsc#912889)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=912889"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=933922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=935119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=939246"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=943816"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=950114"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected polkit packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-Polkit-1_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libpolkit0-0.113-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpolkit0-debuginfo-0.113-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"polkit-0.113-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"polkit-debuginfo-0.113-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"polkit-debugsource-0.113-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"polkit-devel-0.113-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"polkit-devel-debuginfo-0.113-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"typelib-1_0-Polkit-1_0-0.113-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpolkit0-32bit-0.113-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpolkit0-debuginfo-32bit-0.113-6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpolkit0 / libpolkit0-32bit / libpolkit0-debuginfo / etc");
}
