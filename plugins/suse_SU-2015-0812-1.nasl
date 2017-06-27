#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0812-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83723);
  script_version("$Revision: 2.16 $");
  script_cvs_date("$Date: 2017/04/10 13:19:30 $");

  script_cve_id("CVE-2009-4020", "CVE-2011-1090", "CVE-2011-1163", "CVE-2011-1476", "CVE-2011-1477", "CVE-2011-1493", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1585", "CVE-2011-4127", "CVE-2011-4132", "CVE-2011-4913", "CVE-2011-4914", "CVE-2012-2313", "CVE-2012-2319", "CVE-2012-3400", "CVE-2012-6657", "CVE-2013-2147", "CVE-2013-4299", "CVE-2013-6405", "CVE-2013-6463", "CVE-2014-0181", "CVE-2014-1874", "CVE-2014-3184", "CVE-2014-3185", "CVE-2014-3673", "CVE-2014-3917", "CVE-2014-4652", "CVE-2014-4653", "CVE-2014-4654", "CVE-2014-4655", "CVE-2014-4656", "CVE-2014-4667", "CVE-2014-5471", "CVE-2014-5472", "CVE-2014-9090", "CVE-2014-9322", "CVE-2014-9420", "CVE-2014-9584", "CVE-2015-2041");
  script_bugtraq_id(46766, 46878, 46935, 47007, 47009, 47185, 47381, 50663, 51176, 53401, 53965, 54279, 60280, 63183, 63999, 64669, 65459, 67034, 67699, 68162, 68163, 68164, 68170, 68224, 69396, 69428, 69768, 69781, 69803, 70883, 71250, 71685, 71717, 71883, 72729);
  script_osvdb_id(74637, 83548, 83549, 100422, 106174, 108386, 108389, 108390, 108451, 108473, 110564, 110565, 110567, 110568, 110569, 110570, 110571, 110572, 110732, 113727, 115163, 115919, 116075, 116767, 118659);

  script_name(english:"SUSE SLES10 Security Update : kernel (SUSE-SU-2015:0812-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 10 SP4 LTSS kernel was updated to receive
various security and bugfixes.

The following security bugs have been fixed :

CVE-2015-2041: A information leak in the llc2_timeout_table was fixed
(bnc#919007).

CVE-2014-9322: arch/x86/kernel/entry_64.S in the Linux kernel did not
properly handle faults associated with the Stack Segment (SS) segment
register, which allowed local users to gain privileges by triggering
an IRET instruction that leads to access to a GS Base address from the
wrong space (bnc#910251).

CVE-2014-9090: The do_double_fault function in arch/x86/kernel/traps.c
in the Linux kernel did not properly handle faults associated with the
Stack Segment (SS) segment register, which allowed local users to
cause a denial of service (panic) via a modify_ldt system call, as
demonstrated by sigreturn_32 in the 1-clock-tests test suite
(bnc#907818).

CVE-2014-4667: The sctp_association_free function in
net/sctp/associola.c in the Linux kernel did not properly manage a
certain backlog value, which allowed remote attackers to cause a
denial of service (socket outage) via a crafted SCTP packet
(bnc#885422).

CVE-2014-3673: The SCTP implementation in the Linux kernel allowed
remote attackers to cause a denial of service (system crash) via a
malformed ASCONF chunk, related to net/sctp/sm_make_chunk.c and
net/sctp/sm_statefuns.c (bnc#902346).

CVE-2014-3185: Multiple buffer overflows in the
command_port_read_callback function in drivers/usb/serial/whiteheat.c
in the Whiteheat USB Serial Driver in the Linux kernel allowed
physically proximate attackers to execute arbitrary code or cause a
denial of service (memory corruption and system crash) via a crafted
device that provides a large amount of (1) EHCI or (2) XHCI data
associated with a bulk response (bnc#896391).

CVE-2014-3184: The report_fixup functions in the HID subsystem in the
Linux kernel might have allowed physically proximate attackers to
cause a denial of service (out-of-bounds write) via a crafted device
that provides a small report descriptor, related to (1)
drivers/hid/hid-cherry.c, (2) drivers/hid/hid-kye.c, (3)
drivers/hid/hid-lg.c, (4) drivers/hid/hid-monterey.c, (5)
drivers/hid/hid-petalynx.c, and (6) drivers/hid/hid-sunplus.c
(bnc#896390).

CVE-2014-1874: The security_context_to_sid_core function in
security/selinux/ss/services.c in the Linux kernel allowed local users
to cause a denial of service (system crash) by leveraging the
CAP_MAC_ADMIN capability to set a zero-length security context
(bnc#863335).

CVE-2014-0181: The Netlink implementation in the Linux kernel did not
provide a mechanism for authorizing socket operations based on the
opener of a socket, which allowed local users to bypass intended
access restrictions and modify network configurations by using a
Netlink socket for the (1) stdout or (2) stderr of a setuid program
(bnc#875051).

CVE-2013-4299: Interpretation conflict in
drivers/md/dm-snap-persistent.c in the Linux kernel allowed remote
authenticated users to obtain sensitive information or modify data via
a crafted mapping to a snapshot block device (bnc#846404).

CVE-2013-2147: The HP Smart Array controller disk-array driver and
Compaq SMART2 controller disk-array driver in the Linux kernel did not
initialize certain data structures, which allowed local users to
obtain sensitive information from kernel memory via (1) a crafted
IDAGETPCIINFO command for a /dev/ida device, related to the
ida_locked_ioctl function in drivers/block/cpqarray.c or (2) a crafted
CCISS_PASSTHRU32 command for a /dev/cciss device, related to the
cciss_ioctl32_passthru function in drivers/block/cciss.c (bnc#823260).

CVE-2012-6657: The sock_setsockopt function in net/core/sock.c in the
Linux kernel did not ensure that a keepalive action is associated with
a stream socket, which allowed local users to cause a denial of
service (system crash) by leveraging the ability to create a raw
socket (bnc#896779).

CVE-2012-3400: Heap-based buffer overflow in the udf_load_logicalvol
function in fs/udf/super.c in the Linux kernel allowed remote
attackers to cause a denial of service (system crash) or possibly have
unspecified other impact via a crafted UDF filesystem (bnc#769784).

CVE-2012-2319: Multiple buffer overflows in the hfsplus filesystem
implementation in the Linux kernel allowed local users to gain
privileges via a crafted HFS plus filesystem, a related issue to
CVE-2009-4020 (bnc#760902).

CVE-2012-2313: The rio_ioctl function in
drivers/net/ethernet/dlink/dl2k.c in the Linux kernel did not restrict
access to the SIOCSMIIREG command, which allowed local users to write
data to an Ethernet adapter via an ioctl call (bnc#758813).

CVE-2011-4132: The cleanup_journal_tail function in the Journaling
Block Device (JBD) functionality in the Linux kernel 2.6 allowed local
users to cause a denial of service (assertion error and kernel oops)
via an ext3 or ext4 image with an 'invalid log first block value'
(bnc#730118).

CVE-2011-4127: The Linux kernel did not properly restrict SG_IO ioctl
calls, which allowed local users to bypass intended restrictions on
disk read and write operations by sending a SCSI command to (1) a
partition block device or (2) an LVM volume (bnc#738400).

CVE-2011-1585: The cifs_find_smb_ses function in fs/cifs/connect.c in
the Linux kernel did not properly determine the associations between
users and sessions, which allowed local users to bypass CIFS share
authentication by leveraging a mount of a share by a different user
(bnc#687812).

CVE-2011-1494: Integer overflow in the _ctl_do_mpt_command function in
drivers/scsi/mpt2sas/mpt2sas_ctl.c in the Linux kernel might have
allowed local users to gain privileges or cause a denial of service
(memory corruption) via an ioctl call specifying a crafted value that
triggers a heap-based buffer overflow (bnc#685402).

CVE-2011-1495: drivers/scsi/mpt2sas/mpt2sas_ctl.c in the Linux kernel
did not validate (1) length and (2) offset values before performing
memory copy operations, which might allow local users to gain
privileges, cause a denial of service (memory corruption), or obtain
sensitive information from kernel memory via a crafted ioctl call,
related to the _ctl_do_mpt_command and _ctl_diag_read_buffer functions
(bnc#685402).

CVE-2011-1493: Array index error in the rose_parse_national function
in net/rose/rose_subr.c in the Linux kernel allowed remote attackers
to cause a denial of service (heap memory corruption) or possibly have
unspecified other impact by composing FAC_NATIONAL_DIGIS data that
specifies a large number of digipeaters, and then sending this data to
a ROSE socket (bnc#681175).

CVE-2011-4913: The rose_parse_ccitt function in net/rose/rose_subr.c
in the Linux kernel did not validate the FAC_CCITT_DEST_NSAP and
FAC_CCITT_SRC_NSAP fields, which allowed remote attackers to (1) cause
a denial of service (integer underflow, heap memory corruption, and
panic) via a small length value in data sent to a ROSE socket, or (2)
conduct stack-based buffer overflow attacks via a large length value
in data sent to a ROSE socket (bnc#681175).

CVE-2011-4914: The ROSE protocol implementation in the Linux kernel
did not verify that certain data-length values are consistent with the
amount of data sent, which might allow remote attackers to obtain
sensitive information from kernel memory or cause a denial of service
(out-of-bounds read) via crafted data to a ROSE socket (bnc#681175).

CVE-2011-1476: Integer underflow in the Open Sound System (OSS)
subsystem in the Linux kernel on unspecified non-x86 platforms allowed
local users to cause a denial of service (memory corruption) by
leveraging write access to /dev/sequencer (bnc#681999).

CVE-2011-1477: Multiple array index errors in sound/oss/opl3.c in the
Linux kernel allowed local users to cause a denial of service (heap
memory corruption) or possibly gain privileges by leveraging write
access to /dev/sequencer (bnc#681999).

CVE-2011-1163: The osf_partition function in fs/partitions/osf.c in
the Linux kernel did not properly handle an invalid number of
partitions, which might allow local users to obtain potentially
sensitive information from kernel heap memory via vectors related to
partition-table parsing (bnc#679812).

CVE-2011-1090: The __nfs4_proc_set_acl function in fs/nfs/nfs4proc.c
in the Linux kernel stored NFSv4 ACL data in memory that is allocated
by kmalloc but not properly freed, which allowed local users to cause
a denial of service (panic) via a crafted attempt to set an ACL
(bnc#677286).

CVE-2014-9584: The parse_rock_ridge_inode_internal function in
fs/isofs/rock.c in the Linux kernel did not validate a length value in
the Extensions Reference (ER) System Use Field, which allowed local
users to obtain sensitive information from kernel memory via a crafted
iso9660 image (bnc#912654).

CVE-2014-9420: The rock_continue function in fs/isofs/rock.c in the
Linux kernel did not restrict the number of Rock Ridge continuation
entries, which allowed local users to cause a denial of service
(infinite loop, and system crash or hang) via a crafted iso9660 image
(bnc#911325).

CVE-2014-5471: Stack consumption vulnerability in the
parse_rock_ridge_inode_internal function in fs/isofs/rock.c in the
Linux kernel allowed local users to cause a denial of service
(uncontrolled recursion, and system crash or reboot) via a crafted
iso9660 image with a CL entry referring to a directory entry that has
a CL entry (bnc#892490).

CVE-2014-5472: The parse_rock_ridge_inode_internal function in
fs/isofs/rock.c in the Linux kernel allowed local users to cause a
denial of service (unkillable mount process) via a crafted iso9660
image with a self-referential CL entry (bnc#892490).

CVE-2014-3917: kernel/auditsc.c in the Linux kernel, when
CONFIG_AUDITSYSCALL is enabled with certain syscall rules, allowed
local users to obtain potentially sensitive single-bit values from
kernel memory or cause a denial of service (OOPS) via a large value of
a syscall number (bnc#880484).

CVE-2014-4652: Race condition in the tlv handler functionality in the
snd_ctl_elem_user_tlv function in sound/core/control.c in the ALSA
control implementation in the Linux kernel allowed local users to
obtain sensitive information from kernel memory by leveraging
/dev/snd/controlCX access (bnc#883795).

CVE-2014-4654: The snd_ctl_elem_add function in sound/core/control.c
in the ALSA control implementation in the Linux kernel did not check
authorization for SNDRV_CTL_IOCTL_ELEM_REPLACE commands, which allowed
local users to remove kernel controls and cause a denial of service
(use-after-free and system crash) by leveraging /dev/snd/controlCX
access for an ioctl call (bnc#883795).

CVE-2014-4655: The snd_ctl_elem_add function in sound/core/control.c
in the ALSA control implementation in the Linux kernel did not
properly maintain the user_ctl_count value, which allowed local users
to cause a denial of service (integer overflow and limit bypass) by
leveraging /dev/snd/controlCX access for a large number of
SNDRV_CTL_IOCTL_ELEM_REPLACE ioctl calls (bnc#883795).

CVE-2014-4653: sound/core/control.c in the ALSA control implementation
in the Linux kernel did not ensure possession of a read/write lock,
which allowed local users to cause a denial of service
(use-after-free) and obtain sensitive information from kernel memory
by leveraging /dev/snd/controlCX access (bnc#883795).

CVE-2014-4656: Multiple integer overflows in sound/core/control.c in
the ALSA control implementation in the Linux kernel allowed local
users to cause a denial of service by leveraging /dev/snd/controlCX
access, related to (1) index values in the snd_ctl_add function and
(2) numid values in the snd_ctl_remove_numid_conflict function
(bnc#883795).

The following non-security bugs have been fixed :

usb: class: cdc-acm: Be careful with bInterval (bnc#891844).

Fix BUG due to racing lookups with reiserfs extended attribute backing
directories (bnc#908382).

reiserfs: eliminate per-super xattr lock (bnc#908382).

reiserfs: eliminate private use of struct file in xattr (bnc#908382).

reiserfs: Expand i_mutex to enclose lookup_one_len (bnc#908382).

reiserfs: fix up lockdep warnings (bnc#908382).

reiserfs: fix xattr root locking/refcount bug (bnc#908382).

reiserfs: make per-inode xattr locking more fine grained (bnc#908382).

reiserfs: remove IS_PRIVATE helpers (bnc#908382).

reiserfs: simplify xattr internal file lookups/opens (bnc#908382).

netfilter: TCP conntrack: improve dead connection detection
(bnc#874307).

Fix kABI breakage due to addition of user_ctl_lock (bnc#883795).

isofs: Fix unchecked printing of ER records.

kabi: protect struct ip_ct_tcp for bnc#874307 fix (bnc#874307).

s390: fix system hang on shutdown because of sclp_con (bnc#883223).

udf: Check component length before reading it.

udf: Check path length when reading symlink.

udf: Verify i_size when loading inode.

udf: Verify symlink size before loading it.

x86, 64-bit: Move K8 B step iret fixup to fault entry asm (preparatory
patch).

x86, asm: Flip RESTORE_ARGS arguments logic (preparatory patch).

x86, asm: Thin down SAVE/RESTORE_* asm macros (preparatory patch).

x86: move dwarf2 related macro to dwarf2.h (preparatory patch).

xen: x86, asm: Flip RESTORE_ARGS arguments logic (preparatory patch).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/677286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/679812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/681175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/681999"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/683282"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/685402"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/687812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/730118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/730200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/738400"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/758813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/760902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/769784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/823260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/846404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/853040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/854722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/863335"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/874307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/875051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/880484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/883223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/883795"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/885422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/891844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/892490"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/896390"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/896391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/896779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/902346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/907818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/908382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/910251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/911325"
  );
  # https://download.suse.com/patch/finder/?keywords=15c960abc4733df91b510dfe4ba2ac6d
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0c2a8dc0"
  );
  # https://download.suse.com/patch/finder/?keywords=2a99948c9c3be4a024a9fa4d408002be
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bb8d1095"
  );
  # https://download.suse.com/patch/finder/?keywords=53c468d2b277f3335fcb5ddb08bda2e4
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0e08f301"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2011-1090.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2011-1163.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2011-1476.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2011-1477.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2011-1493.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2011-1494.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2011-1495.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2011-1585.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2011-4127.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2011-4132.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2011-4913.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2011-4914.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2012-2313.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2012-2319.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2012-3400.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2012-6657.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-2147.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-4299.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-6405.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-6463.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-0181.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-1874.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3184.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3185.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3673.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3917.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-4652.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-4653.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-4654.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-4655.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-4656.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-4667.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-5471.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-5472.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9090.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9322.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9420.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9584.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2041.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150812-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0e1e8d12"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-kdumppae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vmipae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xenpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLES10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES10" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-debug-2.6.16.60-0.132.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-kdump-2.6.16.60-0.132.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.132.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.132.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-bigsmp-2.6.16.60-0.132.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-kdumppae-2.6.16.60-0.132.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-vmi-2.6.16.60-0.132.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-vmipae-2.6.16.60-0.132.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-xenpae-2.6.16.60-0.132.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"kernel-default-2.6.16.60-0.132.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"kernel-source-2.6.16.60-0.132.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"kernel-syms-2.6.16.60-0.132.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-debug-2.6.16.60-0.132.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-kdump-2.6.16.60-0.132.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-smp-2.6.16.60-0.132.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-xen-2.6.16.60-0.132.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-bigsmp-2.6.16.60-0.132.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-kdumppae-2.6.16.60-0.132.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-vmi-2.6.16.60-0.132.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-vmipae-2.6.16.60-0.132.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-xenpae-2.6.16.60-0.132.1")) flag++;


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
