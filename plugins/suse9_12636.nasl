#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(48901);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/21 20:33:29 $");

  script_cve_id("CVE-2007-6206", "CVE-2007-6733", "CVE-2008-0598", "CVE-2008-3275", "CVE-2009-1389", "CVE-2009-4020", "CVE-2009-4537", "CVE-2010-0727", "CVE-2010-1083", "CVE-2010-1088", "CVE-2010-1188", "CVE-2010-2521");

  script_name(english:"SuSE9 Security Update : Linux kernel (YOU Patch Number 12636)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes various security issues and some bugs in the SUSE
Linux Enterprise 9 kernel.

The following security issues were fixed :

  - A crafted NFS write request might have caused a buffer
    overwrite, potentially causing a kernel crash.
    (CVE-2010-2521)

  - The x86_64 copy_to_user implementation might have leaked
    kernel memory depending on specific user buffer setups.
    (CVE-2008-0598)

  - drivers/net/r8169.c in the r8169 driver in the Linux
    kernel did not properly check the size of an Ethernet
    frame that exceeds the MTU, which allows remote
    attackers to (1) cause a denial of service (temporary
    network outage) via a packet with a crafted size, in
    conjunction with certain packets containing A characters
    and certain packets containing E characters; or (2)
    cause a denial of service (system crash) via a packet
    with a crafted size, in conjunction with certain packets
    containing '\0' characters, related to the value of the
    status register and erroneous behavior associated with
    the RxMaxSize register. NOTE: this vulnerability exists
    because of an incorrect fix for CVE-2009-1389.
    (CVE-2009-4537)

  - Use-after-free vulnerability in net/ipv4/tcp_input.c in
    the Linux kernel 2.6 when IPV6_RECVPKTINFO is set on a
    listening socket, allowed remote attackers to cause a
    denial of service (kernel panic) via a SYN packet while
    the socket is in a listening (TCP_LISTEN) state, which
    is not properly handled causes the skb structure to be
    freed. (CVE-2010-1188)

  - The (1) real_lookup and (2) __lookup_hash functions in
    fs/namei.c in the vfs implementation in the Linux kernel
    did not prevent creation of a child dentry for a deleted
    (aka S_DEAD) directory, which allowed local users to
    cause a denial of service ('overflow' of the UBIFS
    orphan area) via a series of attempted file creations
    within deleted directories. (CVE-2008-3275)

  - The nfs_lock function in fs/nfs/file.c in the Linux
    kernel did not properly remove POSIX locks on files that
    are setgid without group-execute permission, which
    allows local users to cause a denial of service (BUG and
    system crash) by locking a file on an NFS filesystem and
    then changing this files permissions, a related issue to
    CVE-2010-0727. (CVE-2007-6733)

  - The do_coredump function in fs/exec.c in Linux kernel
    did not change the UID of a core dump file if it exists
    before a root process creates a core dump in the same
    location, which might have allowed local users to obtain
    sensitive information. (CVE-2007-6206)

  - fs/namei.c in the Linux kernel did not always follow NFS
    automount 'symlinks,' which allowed attackers to have an
    unknown impact, related to LOOKUP_FOLLOW.
    (CVE-2010-1088)

  - Stack-based buffer overflow in the hfs subsystem in the
    Linux kernel allowed remote attackers to have an
    unspecified impact via a crafted Hierarchical File
    System (HFS) filesystem, related to the hfs_readdir
    function in fs/hfs/dir.c. (CVE-2009-4020)

  - The processcompl_compat function in
    drivers/usb/core/devio.c in Linux kernel did not clear
    the transfer buffer before returning to userspace when a
    USB command fails, which might have made it easier for
    physically proximate attackers to obtain sensitive
    information (kernel memory). (CVE-2010-1083)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-6206.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-6733.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-0598.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-3275.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1389.html"
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
    value:"http://support.novell.com/security/cve/CVE-2010-0727.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1083.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1088.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1188.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2521.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 12636.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(16, 20, 119, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 9 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-bigsmp-2.6.5-7.323")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-debug-2.6.5-7.323")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-default-2.6.5-7.323")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-smp-2.6.5-7.323")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-source-2.6.5-7.323")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-syms-2.6.5-7.323")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-um-2.6.5-7.323")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-xen-2.6.5-7.323")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-xenpae-2.6.5-7.323")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"um-host-install-initrd-1.0-48.36")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"um-host-kernel-2.6.5-7.323")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"xen-kmp-3.0.4_2.6.5_7.323-0.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
