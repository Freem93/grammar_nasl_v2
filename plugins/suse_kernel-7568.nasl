#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(55468);
  script_version ("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/05/17 11:12:38 $");

  script_cve_id("CVE-2009-4536", "CVE-2010-0008", "CVE-2010-4251", "CVE-2011-0191", "CVE-2011-1010", "CVE-2011-1012", "CVE-2011-1016", "CVE-2011-1017", "CVE-2011-1160", "CVE-2011-1163", "CVE-2011-1180", "CVE-2011-1182", "CVE-2011-1476", "CVE-2011-1477", "CVE-2011-1493", "CVE-2011-1573", "CVE-2011-1577", "CVE-2011-1585", "CVE-2011-1593");

  script_name(english:"SuSE 10 Security Update : Linux kernel (ZYPP Patch Number 7568)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update for the SUSE Linux Enterprise 10 SP3 kernel fixes
several security issues and bugs.

The following security issues were fixed :

  - Multiple integer overflows in the next_pidmap function
    in kernel/pid.c in the Linux kernel allowed local users
    to cause a denial of service (system crash) via a
    crafted (1) getdents or (2) readdir system call.
    (CVE-2011-1593)

  - Only half of the fix for this vulnerability was only
    applied, the fix was completed now. Original text:
    drivers/net/e1000/e1000_main.c in the e1000 driver in
    the Linux kernel handled Ethernet frames that exceed the
    MTU by processing certain trailing payload data as if it
    were a complete frame, which allows remote attackers to
    bypass packet filters via a large packet with a crafted
    payload. (CVE-2009-4536)

  - Boundschecking was missing in AARESOLVE_OFFSET in the
    SCTP protocol, which allowed local attackers to
    overwrite kernel memory and so escalate privileges or
    crash the kernel. (CVE-2011-1573)

  - Heap-based buffer overflow in the ldm_frag_add function
    in fs/partitions/ldm.c in the Linux kernel might have
    allowed local users to gain privileges or obtain
    sensitive information via a crafted LDM partition table.
    (CVE-2011-1017)

  - When using a setuid root mount.cifs, local users could
    hijack password protected mounted CIFS shares of other
    local users. (CVE-2011-1585)

  - Kernel information via the TPM devices could by used by
    local attackers to read kernel memory. (CVE-2011-1160)

  - The Linux kernel automatically evaluated partition
    tables of storage devices. The code for evaluating EFI
    GUID partitions (in fs/partitions/efi.c) contained a bug
    that causes a kernel oops on certain corrupted GUID
    partition tables, which might be used by local attackers
    to crash the kernel or potentially execute code.
    (CVE-2011-1577)

  - In the IrDA module, length fields provided by a peer for
    names and attributes may be longer than the destination
    array sizes and were not checked, this allowed local
    attackers (close to the irda port) to potentially
    corrupt memory. (CVE-2011-1180)

  - A system out of memory condition (denial of service)
    could be triggered with a large socket backlog,
    exploitable by local users. This has been addressed by
    backlog limiting. (CVE-2010-4251)

  - The Radeon GPU drivers in the Linux kernel did not
    properly validate data related to the AA resolve
    registers, which allowed local users to write to
    arbitrary memory locations associated with (1) Video RAM
    (aka VRAM) or (2) the Graphics Translation Table (GTT)
    via crafted values. (CVE-2011-1016)

  - When parsing the FAC_NATIONAL_DIGIS facilities field, it
    was possible for a remote host to provide more
    digipeaters than expected, resulting in heap corruption.
    (CVE-2011-1493)

  - Local attackers could send signals to their programs
    that looked like coming from the kernel, potentially
    gaining privileges in the context of setuid programs.
    (CVE-2011-1182)

  - The code for evaluating LDM partitions (in
    fs/partitions/ldm.c) contained bugs that could crash the
    kernel for certain corrupted LDM partitions.
    (CVE-2011-1017 / CVE-2011-1012)

  - The code for evaluating Mac partitions (in
    fs/partitions/mac.c) contained a bug that could crash
    the kernel for certain corrupted Mac partitions.
    (CVE-2011-1010)

  - The code for evaluating OSF partitions (in
    fs/partitions/osf.c) contained a bug that leaks data
    from kernel heap memory to userspace for certain
    corrupted OSF partitions. (CVE-2011-1163)

  - Specially crafted requests may be written to
    /dev/sequencer resulting in an underflow when
    calculating a size for a copy_from_user() operation in
    the driver for MIDI interfaces. On x86, this just
    returns an error, but it could have caused memory
    corruption on other architectures. Other malformed
    requests could have resulted in the use of uninitialized
    variables. (CVE-2011-1476)

  - Due to a failure to validate user-supplied indexes in
    the driver for Yamaha YM3812 and OPL-3 chips, a
    specially crafted ioctl request could have been sent to
    /dev/sequencer, resulting in reading and writing beyond
    the bounds of heap buffers, and potentially allowing
    privilege escalation. (CVE-2011-1477)

  - A information leak in the XFS geometry calls could be
    used by local attackers to gain access to kernel
    information. (CVE-2011-0191)

  - The sctp_rcv_ootb function in the SCTP implementation in
    the Linux kernel allowed remote attackers to cause a
    denial of service (infinite loop) via (1) an Out Of The
    Blue (OOTB) chunk or (2) a chunk of zero length.
    (CVE-2010-0008)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-4536.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0008.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4251.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0191.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1012.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1017.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1160.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1163.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1180.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1182.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1476.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1477.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1493.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1573.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1577.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1585.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1593.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7568.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-bigsmp-2.6.16.60-0.79.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-debug-2.6.16.60-0.79.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-default-2.6.16.60-0.79.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-kdump-2.6.16.60-0.79.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-kdumppae-2.6.16.60-0.79.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-smp-2.6.16.60-0.79.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-source-2.6.16.60-0.79.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-syms-2.6.16.60-0.79.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-vmi-2.6.16.60-0.79.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-vmipae-2.6.16.60-0.79.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-xen-2.6.16.60-0.79.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-xenpae-2.6.16.60-0.79.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
