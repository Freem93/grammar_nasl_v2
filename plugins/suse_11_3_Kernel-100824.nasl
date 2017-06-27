#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update Kernel-3038.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75548);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:55:23 $");

  script_cve_id("CVE-2010-2524", "CVE-2010-2537", "CVE-2010-2538", "CVE-2010-2798", "CVE-2010-3110");

  script_name(english:"openSUSE Security Update : Kernel (openSUSE-SU-2010:0592-1)");
  script_summary(english:"Check for the Kernel-3038 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of the openSUSE 11.3 kernel brings the kernel to version
2.6.34.4 and contains a lot of bug and security fixes

CVE-2010-3110: Missing bounds checks in several ioctls of the Novell
Client novfs /proc interface allowed unprivileged local users to crash
the kernel or even execute code in kernel context.

CVE-2010-2524: a malicious local user could fill the cache used by
CIFS do perform dns lookups with chosen data, therefore tricking the
kernel into mounting a wrong CIFS server.

CVE-2010-2798: a local user could trigger a NULL derefence on a gfs2
file system

CVE-2010-2537: a local user could overwrite append-only files on a
btrfs file system

CVE-2010-2538: a local user could read kernel memory of a btrfs file
system"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-09/msg00009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=529535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=584720"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=586643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=594362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=599671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=608300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=610362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=610828"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=615656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=617530"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=617912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=618678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=619021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=619416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=619440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=619727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=621598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=623005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=623472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=624118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=624587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=624606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=624814"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=625339"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=627212"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=627310"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=627386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=627447"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=629908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=631066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=631185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=631319"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/24");
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
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"kernel-debug-2.6.34.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-debug-base-2.6.34.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-debug-devel-2.6.34.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-default-2.6.34.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-default-base-2.6.34.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-default-devel-2.6.34.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-desktop-2.6.34.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-desktop-base-2.6.34.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-desktop-devel-2.6.34.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-devel-2.6.34.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-ec2-devel-2.6.34.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-pae-2.6.34.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-pae-base-2.6.34.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-pae-devel-2.6.34.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-source-2.6.34.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-source-vanilla-2.6.34.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-syms-2.6.34.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-trace-2.6.34.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-trace-base-2.6.34.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-trace-devel-2.6.34.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vanilla-2.6.34.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vanilla-base-2.6.34.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vanilla-devel-2.6.34.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vmi-devel-2.6.34.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-xen-2.6.34.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-xen-base-2.6.34.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-xen-devel-2.6.34.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"preload-kmp-default-1.1_k2.6.34.4_0.1-19.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"preload-kmp-desktop-1.1_k2.6.34.4_0.1-19.1.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-debug-base / kernel-debug-devel / etc");
}
