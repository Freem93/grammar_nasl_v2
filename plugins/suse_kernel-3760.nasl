#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-3760.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27295);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/06/13 20:11:36 $");

  script_cve_id("CVE-2006-7203", "CVE-2007-1496", "CVE-2007-1497", "CVE-2007-1861", "CVE-2007-2242", "CVE-2007-2453", "CVE-2007-2876");

  script_name(english:"openSUSE 10 Security Update : kernel (kernel-3760)");
  script_summary(english:"Check for the kernel-3760 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update fixes the following security problems :

  - CVE-2007-1861: The nl_fib_lookup function in
    net/ipv4/fib_frontend.c allows attackers to cause a
    denial of service (kernel panic) via NETLINK_FIB_LOOKUP
    replies, which trigger infinite recursion and a stack
    overflow.

  - CVE-2007-1496: nfnetlink_log in netfilter allows
    attackers to cause a denial of service (crash) via
    unspecified vectors involving the (1) nfulnl_recv_config
    function, (2) using 'multiple packets per netlink
    message', and (3) bridged packets, which trigger a NULL
    pointer dereference.

  - CVE-2007-1497: nf_conntrack in netfilter does not set
    nfctinfo during reassembly of fragmented packets, which
    leaves the default value as IP_CT_ESTABLISHED and might
    allow remote attackers to bypass certain rulesets using
    IPv6 fragments.

    Please note that the connection tracking option for IPv6
    is not enabled in any currently shipping SUSE Linux
    kernel, so it does not affect SUSE Linux default
    kernels.

  - CVE-2007-2242: The IPv6 protocol allows remote attackers
    to cause a denial of service via crafted IPv6 type 0
    route headers (IPV6_RTHDR_TYPE_0) that create network
    amplification between two routers.

    The behaviour has been disabled by default, and the
    patch introduces a new sysctl with which the
    administrator can reenable it again.

  - CVE-2006-7203: The compat_sys_mount function in
    fs/compat.c allows local users to cause a denial of
    service (NULL pointer dereference and oops) by mounting
    a smbfs file system in compatibility mode ('mount -t
    smbfs').

  - CVE-2007-2453: Seeding of the kernel random generator on
    boot did not work correctly due to a programming mistake
    and so the kernel might have more predictable random
    numbers than assured.

  - CVE-2007-2876: A NULL pointer dereference in SCTP
    connection tracking could be caused by a remote attacker
    by sending specially crafted packets. Note that this
    requires SCTP set-up and active to be exploitable.

and the following non security bugs :

    - patches.fixes/cpufreq_fix_limited_on_battery.patch:
      Fix limited freq when booted on battery. [#231107]

    - patches.fixes/usb-keyspan-regression-fix.patch: USB:
      keyspan regression fix [#240919]

  - -
    patches.fixes/hpt366-dont-check-enablebits-for-hpt36x.pa
    tch: hpt366: don't check enablebits for HPT36x [#278696]"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xenpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.2", reference:"kernel-bigsmp-2.6.18.8-0.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-default-2.6.18.8-0.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-source-2.6.18.8-0.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-syms-2.6.18.8-0.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-xen-2.6.18.8-0.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kernel-xenpae-2.6.18.8-0.5") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-bigsmp / kernel-default / kernel-source / kernel-syms / etc");
}
