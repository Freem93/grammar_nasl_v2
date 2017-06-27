#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-550.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(85525);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/10/22 14:14:59 $");

  script_cve_id("CVE-2015-2594", "CVE-2015-3456");

  script_name(english:"openSUSE Security Update : virtualbox (openSUSE-2015-550) (Venom)");
  script_summary(english:"Check for the openSUSE-2015-550 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Version bump to 4.2.32 bnc#938408 CVE-2015-2594

  - Storage: fixed a crash when taking snapshots (4.2.30
    regression)

  - ExtPack: don't fail if the TMP directory contains
    non-latin1 characters (bug #14159)

  - Main: implemented dedicated event processing queue

  - Linux hosts: fixed a bug which made the netfilter driver
    ignore certain events (bug #12264) 

Also included from Version bump to 4.2.30 bnc#935900 CVE-2015-3456 :

  - Various small fixes here and there

  - Fix the multiinstall on kernel modules to avoid
    conflicts bnc#925663

  - Drop smap.diff fails to apply to the latest release"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=925663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=935900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=938408"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected virtualbox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-desktop-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/10");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/19");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"python-virtualbox-4.2.32-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-virtualbox-debuginfo-4.2.32-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-4.2.32-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-debuginfo-4.2.32-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-debugsource-4.2.32-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-devel-4.2.32-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-default-4.2.32_k3.11.10_29-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-default-debuginfo-4.2.32_k3.11.10_29-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-desktop-4.2.32_k3.11.10_29-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-desktop-debuginfo-4.2.32_k3.11.10_29-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-pae-4.2.32_k3.11.10_29-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-pae-debuginfo-4.2.32_k3.11.10_29-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-tools-4.2.32-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-tools-debuginfo-4.2.32-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-x11-4.2.32-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-x11-debuginfo-4.2.32-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-default-4.2.32_k3.11.10_29-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-default-debuginfo-4.2.32_k3.11.10_29-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-desktop-4.2.32_k3.11.10_29-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-desktop-debuginfo-4.2.32_k3.11.10_29-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-pae-4.2.32_k3.11.10_29-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-pae-debuginfo-4.2.32_k3.11.10_29-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-source-4.2.32-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-qt-4.2.32-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-qt-debuginfo-4.2.32-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-websrv-4.2.32-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-websrv-debuginfo-4.2.32-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-virtualbox-4.3.30-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-virtualbox-debuginfo-4.3.30-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-4.3.30-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-debuginfo-4.3.30-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-debugsource-4.3.30-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-devel-4.3.30-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-desktop-icons-4.3.30-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-default-4.3.30_k3.16.7_21-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-default-debuginfo-4.3.30_k3.16.7_21-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-desktop-4.3.30_k3.16.7_21-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-desktop-debuginfo-4.3.30_k3.16.7_21-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-pae-4.3.30_k3.16.7_21-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-pae-debuginfo-4.3.30_k3.16.7_21-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-tools-4.3.30-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-tools-debuginfo-4.3.30-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-x11-4.3.30-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-x11-debuginfo-4.3.30-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-default-4.3.30_k3.16.7_21-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-default-debuginfo-4.3.30_k3.16.7_21-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-desktop-4.3.30_k3.16.7_21-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-desktop-debuginfo-4.3.30_k3.16.7_21-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-pae-4.3.30_k3.16.7_21-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-pae-debuginfo-4.3.30_k3.16.7_21-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-source-4.3.30-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-qt-4.3.30-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-qt-debuginfo-4.3.30-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-websrv-4.3.30-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-websrv-debuginfo-4.3.30-17.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-virtualbox / python-virtualbox-debuginfo / virtualbox / etc");
}
