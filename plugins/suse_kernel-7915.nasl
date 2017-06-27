#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(59161);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/07/24 02:36:58 $");

  script_cve_id("CVE-2010-3873", "CVE-2010-4164", "CVE-2010-4249", "CVE-2011-1080", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-1173", "CVE-2011-2203", "CVE-2011-2213", "CVE-2011-2525", "CVE-2011-2534", "CVE-2011-2699", "CVE-2011-3209");

  script_name(english:"SuSE 10 Security Update : Linux kernel (ZYPP Patch Number 7915)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This Linux kernel update fixes various security issues and bugs in the
SUSE Linux Enterprise 10 SP4 kernel.

This update fixes the following security issues :

  - X.25 remote DoS. (CVE-2010-3873). (bnc#651219)

  - X.25 remote Dos. (CVE-2010-4164). (bnc#653260)

  - 1 socket local DoS. (CVE-2010-4249). (bnc#655696)

  - ebtables infoleak. (CVE-2011-1080). (bnc#676602)

  - netfilter: arp_tables infoleak to userspace.
    (CVE-2011-1170). (bnc#681180)

  - netfilter: ip_tables infoleak to userspace.
    (CVE-2011-1171). (bnc#681181)

  - netfilter: ip6_tables infoleak to userspace.
    (CVE-2011-1172). (bnc#681185)

  - econet 4 byte infoleak. (CVE-2011-1173). (bnc#681186)

  - hfs NULL pointer dereference. (CVE-2011-2203).
    (bnc#699709)

  - inet_diag infinite loop. (CVE-2011-2213). (bnc#700879)

  - netfilter: ipt_CLUSTERIP buffer overflow.
    (CVE-2011-2534). (bnc#702037)

  - ipv6: make fragment identifications less predictable.
    (CVE-2011-2699). (bnc#707288)

  - clock_gettime() panic. (CVE-2011-3209). (bnc#726064)

  - qdisc NULL dereference (CVE-2011-2525) This update also
    fixes the following non-security issues:. (bnc#735612)

  - New timesource for VMware platform. (bnc#671124)

  - usblp crashes after the printer is unplugged for the
    second time. (bnc#673343)

  - Data corruption with mpt2sas driver. (bnc#704253)

  - NIC Bond no longer works when booting the XEN kernel.
    (bnc#716437)

  - 'reboot=b' kernel command line hangs system on reboot.
    (bnc#721267)

  - kernel panic at iscsi_xmitwork function. (bnc#721351)

  - NFS supplementary group permissions. (bnc#725878)

  - IBM LTC System z Maintenance Kernel Patches (#59).
    (bnc#726843)

  - NFS slowness. (bnc#727597)

  - IBM LTC System z maintenance kernel patches (#60).
    (bnc#728341)

  - propagate MAC-address to VLAN-interface. (bnc#729117)

  - ipmi deadlock in start_next_msg. (bnc#730749)

  - ext3 filesystem corruption after crash. (bnc#731770)

  - IBM LTC System z maintenance kernel patches (#61).
    (bnc#732375)

  - hangs when offlining a CPU core. (bnc#733407)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3873.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4164.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4249.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1080.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1170.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1171.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1172.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1173.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2203.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2213.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2525.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2534.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2699.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-3209.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7915.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.93.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.93.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.93.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.93.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.93.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-debug-2.6.16.60-0.93.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.93.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-kdump-2.6.16.60-0.93.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.93.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.93.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.93.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.93.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
