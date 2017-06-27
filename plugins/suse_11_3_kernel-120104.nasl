#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-5605.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75557);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:55:23 $");

  script_cve_id("CVE-2010-3880", "CVE-2011-1478", "CVE-2011-1576", "CVE-2011-1770", "CVE-2011-2203", "CVE-2011-2213", "CVE-2011-2525", "CVE-2011-2534", "CVE-2011-2699", "CVE-2011-2723", "CVE-2011-2898", "CVE-2011-4081", "CVE-2011-4604");

  script_name(english:"openSUSE Security Update : kernel (openSUSE-SU-2012:0206-1)");
  script_summary(english:"Check for the kernel-5605 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE 11.3 kernel was updated to fix various bugs and security
issues.

Following security issues have been fixed: CVE-2011-4604: If root does
read() on a specific socket, it's possible to corrupt (kernel) memory
over network, with an ICMP packet, if the B.A.T.M.A.N. mesh protocol
is used.

CVE-2011-2525: A flaw allowed the tc_fill_qdisc() function in the
Linux kernels packet scheduler API implementation to be called on
built-in qdisc structures. A local, unprivileged user could have used
this flaw to trigger a NULL pointer dereference, resulting in a denial
of service.

CVE-2011-2699: Fernando Gont discovered that the IPv6 stack used
predictable fragment identification numbers. A remote attacker could
exploit this to exhaust network resources, leading to a denial of
service.

CVE-2011-2213: The inet_diag_bc_audit function in net/ipv4/inet_diag.c
in the Linux kernel did not properly audit INET_DIAG bytecode, which
allowed local users to cause a denial of service (kernel infinite
loop) via crafted INET_DIAG_REQ_BYTECODE instructions in a netlink
message, as demonstrated by an INET_DIAG_BC_JMP instruction with a
zero yes value, a different vulnerability than CVE-2010-3880.

CVE-2011-1576: The Generic Receive Offload (GRO) implementation in the
Linux kernel allowed remote attackers to cause a denial of service via
crafted VLAN packets that are processed by the napi_reuse_skb
function, leading to (1) a memory leak or (2) memory corruption, a
different vulnerability than CVE-2011-1478.

CVE-2011-2534: Buffer overflow in the clusterip_proc_write function in
net/ipv4/netfilter/ipt_CLUSTERIP.c in the Linux kernel might have
allowed local users to cause a denial of service or have unspecified
other impact via a crafted write operation, related to string data
that lacks a terminating '\0' character.

CVE-2011-1770: Integer underflow in the dccp_parse_options function
(net/dccp/options.c) in the Linux kernel allowed remote attackers to
cause a denial of service via a Datagram Congestion Control Protocol
(DCCP) packet with an invalid feature options length, which triggered
a buffer over-read.

CVE-2011-2723: The skb_gro_header_slow function in
include/linux/netdevice.h in the Linux kernel, when Generic Receive
Offload (GRO) is enabled, reset certain fields in incorrect
situations, which allowed remote attackers to cause a denial of
service (system crash) via crafted network traffic.

CVE-2011-2898: A kernel information leak in the AF_PACKET protocol was
fixed which might have allowed local attackers to read kernel memory.

CVE-2011-2203: A NULL ptr dereference on mounting corrupt hfs
filesystems was fixed which could be used by local attackers to crash
the kernel.

CVE-2011-4081: Using the crypto interface a local user could Oops the
kernel by writing to a AF_ALG socket."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-02/msg00008.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=691052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=692498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=698450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=699709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=700879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=702037"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=707288"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=709764"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=710235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=726788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=728661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=735612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=736149"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-extra");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/04");
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

if ( rpm_check(release:"SUSE11.3", reference:"kernel-debug-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-debug-base-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-debug-devel-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-default-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-default-base-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-default-devel-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-desktop-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-desktop-base-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-desktop-devel-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-devel-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-ec2-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-ec2-base-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-ec2-devel-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-ec2-extra-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-pae-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-pae-base-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-pae-devel-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-source-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-source-vanilla-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-syms-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-trace-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-trace-base-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-trace-devel-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vanilla-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vanilla-base-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vanilla-devel-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vmi-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vmi-base-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vmi-devel-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-xen-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-xen-base-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-xen-devel-2.6.34.10-0.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"preload-kmp-default-1.1_k2.6.34.10_0.6-19.1.37") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"preload-kmp-desktop-1.1_k2.6.34.10_0.6-19.1.37") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
