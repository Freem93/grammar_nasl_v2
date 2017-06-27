#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59148);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/22 20:42:26 $");

  script_cve_id("CVE-2009-4020", "CVE-2009-4537", "CVE-2010-0410", "CVE-2010-1083", "CVE-2010-1086", "CVE-2010-1088");

  script_name(english:"SuSE 10 Security Update : Linux kernel (ZYPP Patch Number 7015)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a several security issues and various bugs in the
SUSE Linux Enterprise 10 SP 2 kernel. The bugs fixed include a serious
data corruption regression in NFS.

The following security issues were fixed :

  - drivers/net/r8169.c in the r8169 driver in the Linux
    kernel does not properly check the size of an Ethernet
    frame that exceeds the MTU, which allows remote
    attackers to (1) cause a denial of service (temporary
    network outage) via a packet with a crafted size, in
    conjunction with certain packets containing A characters
    and certain packets containing E characters; or (2)
    cause a denial of service (system crash) via a packet
    with a crafted size, in conjunction with certain packets
    containing '0' characters, related to the value of the
    status register and erroneous behavior associated with
    the RxMaxSize register. (CVE-2009-4537)

  - The ULE decapsulation functionality in
    drivers/media/dvb/dvb-core/dvb_net.c in dvb-core in the
    Linux kernel arlier allows attackers to cause a denial
    of service (infinite loop) via a crafted MPEG2-TS frame,
    related to an invalid Payload Pointer ULE.
    (CVE-2010-1086)

  - fs/namei.c in Linux kernel does not always follow NFS
    automount 'symlinks,' which allows attackers to have an
    unknown impact, related to LOOKUP_FOLLOW.
    (CVE-2010-1088)

  - Stack-based buffer overflow in the hfs subsystem in the
    Linux kernel allows remote attackers to have an
    unspecified impact via a crafted Hierarchical File
    System (HFS) filesystem, related to the hfs_readdir
    function in fs/hfs/dir.c. (CVE-2009-4020)

  - The processcompl_compat function in
    drivers/usb/core/devio.c in the Linux kernel does not
    clear the transfer buffer before returning to userspace
    when a USB command fails, which might make it easier for
    physically proximate attackers to obtain sensitive
    information (kernel memory). (CVE-2010-1083)

  - drivers/connector/connector.c in the Linux kernel allows
    local users to cause a denial of service (memory
    consumption and system crash) by sending the kernel many
    NETLINK_CONNECTOR messages. (CVE-2010-0410)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-4020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-4537.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0410.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1083.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1086.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1088.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7015.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20, 119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.42.10")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.42.10")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.42.10")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.42.10")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.42.10")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"kernel-debug-2.6.16.60-0.42.10")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.42.10")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"kernel-kdump-2.6.16.60-0.42.10")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.42.10")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.42.10")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.42.10")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.42.10")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
