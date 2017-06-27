#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-3175.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(49671);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/21 20:21:19 $");

  script_cve_id("CVE-2009-1389", "CVE-2009-4537", "CVE-2010-1087", "CVE-2010-1146", "CVE-2010-1148", "CVE-2010-1162", "CVE-2010-1437", "CVE-2010-1636", "CVE-2010-1641", "CVE-2010-2066", "CVE-2010-2071", "CVE-2010-2226", "CVE-2010-2248", "CVE-2010-2478", "CVE-2010-2492", "CVE-2010-2495", "CVE-2010-2521", "CVE-2010-2524", "CVE-2010-2537", "CVE-2010-2538", "CVE-2010-2798", "CVE-2010-2803", "CVE-2010-2942", "CVE-2010-2946", "CVE-2010-2954", "CVE-2010-2955", "CVE-2010-2959", "CVE-2010-2960", "CVE-2010-3015", "CVE-2010-3078", "CVE-2010-3079", "CVE-2010-3080", "CVE-2010-3081", "CVE-2010-3084", "CVE-2010-3296", "CVE-2010-3297", "CVE-2010-3298", "CVE-2010-3301");

  script_name(english:"openSUSE Security Update : kernel (openSUSE-SU-2010:0664-1)");
  script_summary(english:"Check for the kernel-3175 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This openSUSE 11.2 kernel was updated to 2.6.31.14, fixing several
security issues and bugs.

A lot of ext4 filesystem stability fixes were also added.

Following security issues have been fixed: CVE-2010-3301: Mismatch
between 32bit and 64bit register usage in the system call entry path
could be used by local attackers to gain root privileges. This problem
only affects x86_64 kernels.

CVE-2010-3081: Incorrect buffer handling in the biarch-compat buffer
handling could be used by local attackers to gain root privileges.
This problem affects foremost x86_64, or potentially other biarch
platforms, like PowerPC and S390x.

CVE-2010-3084: A buffer overflow in the ETHTOOL_GRXCLSRLALL code could
be used to crash the kernel or potentially execute code.

CVE-2010-2955: A kernel information leak via the WEXT ioctl was fixed.

CVE-2010-2960: The keyctl_session_to_parent function in
security/keys/keyctl.c in the Linux kernel expects that a certain
parent session keyring exists, which allowed local users to cause a
denial of service (NULL pointer dereference and system crash) or
possibly have unspecified other impact via a KEYCTL_SESSION_TO_PARENT
argument to the keyctl function.

CVE-2010-3080: A double free in an alsa error path was fixed, which
could lead to kernel crashes.

CVE-2010-3079: Fixed a ftrace NULL pointer dereference problem which
could lead to kernel crashes.

CVE-2010-3298: Fixed a kernel information leak in the net/usb/hso
driver.

CVE-2010-3296: Fixed a kernel information leak in the cxgb3 driver.

CVE-2010-3297: Fixed a kernel information leak in the net/eql driver.

CVE-2010-3078: Fixed a kernel information leak in the xfs filesystem.
CVE-2010-2942: Fixed a kernel information leak in the net scheduler
code.

CVE-2010-2954: The irda_bind function in net/irda/af_irda.c in the
Linux kernel did not properly handle failure of the irda_open_tsap
function, which allowed local users to cause a denial of service (NULL
pointer dereference and panic) and possibly have unspecified other
impact via multiple unsuccessful calls to bind on an AF_IRDA (aka
PF_IRDA) socket.

CVE-2010-2226: The xfs_swapext function in fs/xfs/xfs_dfrag.c in the
Linux kernel did not properly check the file descriptors passed to the
SWAPEXT ioctl, which allowed local users to leverage write access and
obtain read access by swapping one file into another file.

CVE-2010-2946: The 'os2' xattr namespace on the jfs filesystem could
be used to bypass xattr namespace rules.

CVE-2010-2959: Integer overflow in net/can/bcm.c in the Controller
Area Network (CAN) implementation in the Linux kernel allowed
attackers to execute arbitrary code or cause a denial of service
(system crash) via crafted CAN traffic.

CVE-2010-3015: Integer overflow in the ext4_ext_get_blocks function in
fs/ext4/extents.c in the Linux kernel allowed local users to cause a
denial of service (BUG and system crash) via a write operation on the
last block of a large file, followed by a sync operation.

CVE-2010-2492: Buffer overflow in the ecryptfs_uid_hash macro in
fs/ecryptfs/messaging.c in the eCryptfs subsystem in the Linux kernel
might have allowed local users to gain privileges or cause a denial of
service (system crash) via unspecified vectors.

CVE-2010-2248: fs/cifs/cifssmb.c in the CIFS implementation in the
Linux kernel allowed remote attackers to cause a denial of service
(panic) via an SMB response packet with an invalid CountHigh value, as
demonstrated by a response from an OS/2 server, related to the
CIFSSMBWrite and CIFSSMBWrite2 functions.

CVE-2010-2803: The drm_ioctl function in drivers/gpu/drm/drm_drv.c in
the Direct Rendering Manager (DRM) subsystem in the Linux kernel
allowed local users to obtain potentially sensitive information from
kernel memory by requesting a large memory-allocation amount.

CVE-2010-2478: A potential buffer overflow in the ETHTOOL_GRXCLSRLALL
ethtool code was fixed which could be used by local attackers to crash
the kernel or potentially execute code.

CVE-2010-2524: The DNS resolution functionality in the CIFS
implementation in the Linux kernel, when CONFIG_CIFS_DFS_UPCALL is
enabled, relies on a user's keyring for the dns_resolver upcall in the
cifs.upcall userspace helper, which allowed local users to spoof the
results of DNS queries and perform arbitrary CIFS mounts via vectors
involving an add_key call, related to a 'cache stuffing' issue and
MS-DFS referrals.

CVE-2010-2798: The gfs2_dirent_find_space function in fs/gfs2/dir.c in
the Linux kernel used an incorrect size value in calculations
associated with sentinel directory entries, which allowed local users
to cause a denial of service (NULL pointer dereference and panic) and
possibly have unspecified other impact by renaming a file in a GFS2
filesystem, related to the gfs2_rename function in
fs/gfs2/ops_inode.c.

CVE-2010-2537: The BTRFS_IOC_CLONE and BTRFS_IOC_CLONE_RANGE ioctls
allowed a local user to overwrite append-only files.

CVE-2010-2538: The BTRFS_IOC_CLONE_RANGE ioctl was subject to an
integer overflow in specifying offsets to copy from a file, which
potentially allowed a local user to read sensitive filesystem data.

CVE-2010-2521: Multiple buffer overflows in fs/nfsd/nfs4xdr.c in the
XDR implementation in the NFS server in the Linux kernel allowed
remote attackers to cause a denial of service (panic) or possibly
execute arbitrary code via a crafted NFSv4 compound WRITE request,
related to the read_buf and nfsd4_decode_compound functions.

CVE-2010-2066: The mext_check_arguments function in
fs/ext4/move_extent.c in the Linux kernel allowed local users to
overwrite an append-only file via a MOVE_EXT ioctl call that specifies
this file as a donor.

CVE-2010-2495: The pppol2tp_xmit function in drivers/net/pppol2tp.c in
the L2TP implementation in the Linux kernel did not properly validate
certain values associated with an interface, which allowed attackers
to cause a denial of service (NULL pointer dereference and OOPS) or
possibly have unspecified other impact via vectors related to a
routing change.

CVE-2010-2071: The btrfs_xattr_set_acl function in fs/btrfs/acl.c in
btrfs in the Linux kernel did not check file ownership before setting
an ACL, which allowed local users to bypass file permissions by
setting arbitrary ACLs, as demonstrated using setfacl.

CVE-2010-1641: The do_gfs2_set_flags function in fs/gfs2/file.c in the
Linux kernel did not verify the ownership of a file, which allowed
local users to bypass intended access restrictions via a SETFLAGS
ioctl request.

CVE-2010-1087: The nfs_wait_on_request function in fs/nfs/pagelist.c
in Linux kernel 2.6.x allowed attackers to cause a denial of service
(Oops) via unknown vectors related to truncating a file and an
operation that is not interruptible.

CVE-2010-1636: The btrfs_ioctl_clone function in fs/btrfs/ioctl.c in
the btrfs functionality in the Linux kernel did not ensure that a
cloned file descriptor has been opened for reading, which allowed
local users to read sensitive information from a write-only file
descriptor.

CVE-2010-1437: Race condition in the find_keyring_by_name function in
security/keys/keyring.c in the Linux kernel allowed local users to
cause a denial of service (memory corruption and system crash) or
possibly have unspecified other impact via keyctl session commands
that trigger access to a dead keyring that is undergoing deletion by
the key_cleanup function.

CVE-2010-1148: The cifs_create function in fs/cifs/dir.c in the Linux
kernel allowed local users to cause a denial of service (NULL pointer
dereference and OOPS) or possibly have unspecified other impact via a
NULL nameidata (aka nd) field in a POSIX file-creation request to a
server that supports UNIX extensions.

CVE-2010-1162: The release_one_tty function in drivers/char/tty_io.c
in the Linux kernel omitted certain required calls to the put_pid
function, which has unspecified impact and local attack vectors.

CVE-2010-1146: The Linux kernel, when a ReiserFS filesystem exists,
did not restrict read or write access to the .reiserfs_priv directory,
which allowed local users to gain privileges by modifying (1) extended
attributes or (2) ACLs, as demonstrated by deleting a file under
.reiserfs_priv/xattrs/.

CVE-2009-4537: drivers/net/r8169.c in the r8169 driver in the Linux
kernel did not properly check the size of an Ethernet frame that
exceeds the MTU, which allowed remote attackers to (1) cause a denial
of service (temporary network outage) via a packet with a crafted
size, in conjunction with certain packets containing A characters and
certain packets containing E characters; or (2) cause a denial of
service (system crash) via a packet with a crafted size, in
conjunction with certain packets containing '\0' characters, related
to the value of the status register and erroneous behavior associated
with the RxMaxSize register. NOTE: this vulnerability exists because
of an incorrect fix for CVE-2009-1389."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-09/msg00045.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=426536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=465707"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=486997"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=508259"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=556837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=557201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=567376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=567860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=567867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=569071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=571494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=573244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=575697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=576026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=583867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=584554"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=585385"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=585927"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=586711"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=587265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=588579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=589280"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=589329"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=589788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=590738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=591371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=593906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=593940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=596031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=596462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=599508"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=599955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=601328"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=602209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=606743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=608576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=610362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=611760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=612213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=612457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=614054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=615141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=616612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=616614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=618156"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=618157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=619850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=620372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=624587"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=628604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=631801"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=632309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=633581"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=633585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=635413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=635425"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=636112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=637436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=637502"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=638274"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=638277"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=639481"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=639482"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=639483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=639708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=639709"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20, 119);

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/24");
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

if ( rpm_check(release:"SUSE11.2", reference:"kernel-debug-2.6.31.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-debug-base-2.6.31.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-debug-devel-2.6.31.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-default-2.6.31.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-default-base-2.6.31.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-default-devel-2.6.31.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-desktop-2.6.31.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-desktop-base-2.6.31.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-desktop-devel-2.6.31.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-pae-2.6.31.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-pae-base-2.6.31.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-pae-devel-2.6.31.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-source-2.6.31.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-source-vanilla-2.6.31.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-syms-2.6.31.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-trace-2.6.31.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-trace-base-2.6.31.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-trace-devel-2.6.31.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-vanilla-2.6.31.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-vanilla-base-2.6.31.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-vanilla-devel-2.6.31.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-xen-2.6.31.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-xen-base-2.6.31.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-xen-devel-2.6.31.14-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"preload-kmp-default-1.1_2.6.31.14_0.1-6.9.26") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"preload-kmp-desktop-1.1_2.6.31.14_0.1-6.9.26") ) flag++;

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
