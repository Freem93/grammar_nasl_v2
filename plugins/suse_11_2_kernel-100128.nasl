#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Updates.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(44411);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/21 20:21:19 $");

  script_cve_id(
    "CVE-2009-3939",
    "CVE-2009-4141",
    "CVE-2009-4536",
    "CVE-2009-4538",
    "CVE-2010-0003",
    "CVE-2010-0006",
    "CVE-2010-0007",
    "CVE-2010-0299"
  );
  script_bugtraq_id(
    37019,
    37519,
    37523,
    37724,
    37762,
    37806,
    37810,
    38437
  );
  script_osvdb_id(
    60201,
    61670,
    61687,
    61769,
    61788,
    61876,
    61984,
    62527
  );
  script_name(english:"SuSE 11.2 Security Update: kernel (2010-01-28)");
  script_summary(english:"Check for the kernel package.");

  script_set_attribute(attribute:"synopsis", value:"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Linux kernel for openSUSE 11.2 was updated to 2.6.31.12 to fix the
following bugs and security issues :

  - The permission of the devtmpfs root directory was
    incorrectly 1777 (instead of 755). If it was used, local
    attackers could escalate privileges. (openSUSE 11.2 does
    not use this filesystem by default). (CVE-2010-0299)

  - The poll_mode_io file for the megaraid_sas driver in the
    Linux kernel 2.6.31.6 and earlier has world-writable
    permissions, which allows local users to change the I/O
    mode of the driver by modifying this file.
    (CVE-2009-3939)

  - ebtables was lacking a CAP_NET_ADMIN check, making it
    possible for local unprivileged attackers to modify the
    network bridge management. (CVE-2010-0007)

  - An information leakage on fatal signals on x86_64
    machines was fixed. (CVE-2010-0003)

  - A race condition in fasync handling could be used by
    local attackers to crash the machine or potentially
    execute code. (CVE-2009-4141)

  - The ipv6_hop_jumbo function in net/ipv6/exthdrs.c in the
    Linux kernel before 2.6.32.4, when network namespaces
    are enabled, allows remote attackers to cause a denial
    of service (NULL pointer dereference) via an invalid
    IPv6 jumbogram. (CVE-2010-0006)

  - drivers/net/e1000/e1000_main.c in the e1000 driver in
    the Linux kernel 2.6.32.3 and earlier handles Ethernet
    frames that exceed the MTU by processing certain
    trailing payload data as if it were a complete frame,
    which allows remote attackers to bypass packet filters
    via a large packet with a crafted payload.
    (CVE-2009-4536)

  - drivers/net/e1000e/netdev.c in the e1000e driver in the
    Linux kernel 2.6.32.3 and earlier does not properly
    check the size of an Ethernet frame that exceeds the
    MTU, which allows remote attackers to have an
    unspecified impact via crafted packets. (CVE-2009-4538)");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.novell.com/show_bug.cgi?id=565027");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=574664");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=573050");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=565904");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=492233");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=552353");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=557180");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=540589");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=565083");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=569902");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=570606");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=568231");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=567340");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=568120");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=537016");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=568120");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=569902");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=568305");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=551356");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=535939");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=564940");
  script_set_attribute(attribute:"solution", value:"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 189, 200, 264, 399);

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/09");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.2", reference:"kernel-debug-2.6.31.12-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-debug-base-2.6.31.12-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-debug-devel-2.6.31.12-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-default-2.6.31.12-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-default-base-2.6.31.12-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-default-devel-2.6.31.12-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-desktop-2.6.31.12-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-desktop-base-2.6.31.12-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-desktop-devel-2.6.31.12-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-pae-2.6.31.12-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-pae-base-2.6.31.12-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-pae-devel-2.6.31.12-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-syms-2.6.31.12-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-trace-2.6.31.12-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-trace-base-2.6.31.12-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-trace-devel-2.6.31.12-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-vanilla-2.6.31.12-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-vanilla-base-2.6.31.12-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-vanilla-devel-2.6.31.12-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-xen-2.6.31.12-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-xen-base-2.6.31.12-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-xen-devel-2.6.31.12-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"preload-kmp-default-1.1_2.6.31.12_0.1-6.9.12") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"preload-kmp-desktop-1.1_2.6.31.12_0.1-6.9.12") ) flag++;

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
