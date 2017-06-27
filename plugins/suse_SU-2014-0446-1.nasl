#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2014:0446-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83616);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_cve_id("CVE-2006-1056", "CVE-2007-0998", "CVE-2012-3497", "CVE-2012-4411", "CVE-2012-4535", "CVE-2012-4537", "CVE-2012-4538", "CVE-2012-4539", "CVE-2012-4544", "CVE-2012-5510", "CVE-2012-5511", "CVE-2012-5513", "CVE-2012-5514", "CVE-2012-5515", "CVE-2012-5634", "CVE-2012-6075", "CVE-2012-6333", "CVE-2013-0153", "CVE-2013-0154", "CVE-2013-1432", "CVE-2013-1442", "CVE-2013-1917", "CVE-2013-1918", "CVE-2013-1919", "CVE-2013-1920", "CVE-2013-1952", "CVE-2013-1964", "CVE-2013-2072", "CVE-2013-2076", "CVE-2013-2077", "CVE-2013-2194", "CVE-2013-2195", "CVE-2013-2196", "CVE-2013-2211", "CVE-2013-2212", "CVE-2013-4329", "CVE-2013-4355", "CVE-2013-4361", "CVE-2013-4368", "CVE-2013-4494", "CVE-2013-4553", "CVE-2013-4554", "CVE-2013-6885", "CVE-2014-1891", "CVE-2014-1892", "CVE-2014-1893", "CVE-2014-1894");
  script_bugtraq_id(17600, 22967, 55410, 55442, 56289, 56498, 56794, 56796, 56797, 56798, 56803, 57159, 57223, 57420, 57745, 58880, 59291, 59292, 59293, 59615, 59617, 59982, 60277, 60282, 60701, 60702, 60703, 60721, 60799, 61424, 62307, 62630, 62708, 62710, 62935, 63494, 63931, 63933, 63983, 65419);
  script_osvdb_id(24746, 24807, 34304, 85199, 85203, 86619, 87298, 87305, 87306, 87307, 88127, 88128, 88129, 88130, 88131, 88655, 88913, 89058, 89319, 89867, 92050, 92563, 92564, 92565, 92983, 92984, 93491, 93820, 93821, 94077, 94442, 94443, 94464, 94600, 95629, 97159, 97770, 97954, 97955, 98290, 99257, 100386, 100387, 100445, 103006, 103007, 103008, 103009);

  script_name(english:"SUSE SLES11 Security Update : Xen (SUSE-SU-2014:0446-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise Server 11 Service Pack 1 LTSS Xen hypervisor
and toolset have been updated to fix various security issues and some
bugs.

The following security issues have been addressed :

XSA-84: CVE-2014-1894: Xen 3.2 (and presumably earlier) exhibit both
problems with the overflow issue being present for more than just the
suboperations listed above. (bnc#860163)

XSA-84: CVE-2014-1892 CVE-2014-1893: Xen 3.3 through 4.1,
while not affected by the above overflow, have a different
overflow issue on FLASK_{GET,SET}BOOL and expose
unreasonably large memory allocation to arbitrary guests.
(bnc#860163)

XSA-84: CVE-2014-1891: The FLASK_{GET,SET}BOOL, FLASK_USER
and FLASK_CONTEXT_TO_SID suboperations of the flask
hypercall are vulnerable to an integer overflow on the input
size. The hypercalls attempt to allocate a buffer which is 1
larger than this size and is therefore vulnerable to integer
overflow and an attempt to allocate then access a zero byte
buffer. (bnc#860163)

XSA-82: CVE-2013-6885: The microcode on AMD 16h 00h through
0Fh processors does not properly handle the interaction
between locked instructions and write-combined memory types,
which allows local users to cause a denial of service
(system hang) via a crafted application, aka the errata 793
issue. (bnc#853049)

XSA-76: CVE-2013-4554: Xen 3.0.3 through 4.1.x (possibly
4.1.6.1), 4.2.x (possibly 4.2.3), and 4.3.x (possibly 4.3.1)
does not properly prevent access to hypercalls, which allows
local guest users to gain privileges via a crafted
application running in ring 1 or 2. (bnc#849668)

XSA-74: CVE-2013-4553: The XEN_DOMCTL_getmemlist hypercall
in Xen 3.4.x through 4.3.x (possibly 4.3.1) does not always
obtain the page_alloc_lock and mm_rwlock in the same order,
which allows local guest administrators to cause a denial of
service (host deadlock). (bnc#849667)

XSA-73: CVE-2013-4494: Xen before 4.1.x, 4.2.x, and 4.3.x
does not take the page_alloc_lock and grant_table.lock in
the same order, which allows local guest administrators with
access to multiple vcpus to cause a denial of service (host
deadlock) via unspecified vectors. (bnc#848657)

XSA-67: CVE-2013-4368: The outs instruction emulation in Xen
3.1.x, 4.2.x, 4.3.x, and earlier, when using FS: or GS:
segment override, uses an uninitialized variable as a
segment base, which allows local 64-bit PV guests to obtain
sensitive information (hypervisor stack content) via
unspecified vectors related to stale data in a segment
register. (bnc#842511)

XSA-66: CVE-2013-4361: The fbld instruction emulation in Xen
3.3.x through 4.3.x does not use the correct variable for
the source effective address, which allows local HVM guests
to obtain hypervisor stack information by reading the values
used by the instruction. (bnc#841766)

XSA-63: CVE-2013-4355: Xen 4.3.x and earlier does not
properly handle certain errors, which allows local HVM
guests to obtain hypervisor stack memory via a (1) port or
(2) memory mapped I/O write or (3) other unspecified
operations related to addresses without associated memory.
(bnc#840592)

XSA-62: CVE-2013-1442: Xen 4.0 through 4.3.x, when using AVX
or LWP capable CPUs, does not properly clear previous data
from registers when using an XSAVE or XRSTOR to extend the
state components of a saved or restored vCPU after touching
other restored extended registers, which allows local guest
OSes to obtain sensitive information by reading the
registers. (bnc#839596)

XSA-61: CVE-2013-4329: The xenlight library (libxl) in Xen
4.0.x through 4.2.x, when IOMMU is disabled, provides access
to a busmastering-capable PCI passthrough device before the
IOMMU setup is complete, which allows local HVM guest
domains to gain privileges or cause a denial of service via
a DMA instruction. (bnc#839618)

XSA-60: CVE-2013-2212: The vmx_set_uc_mode function in Xen
3.3 through 4.3, when disabling chaches, allows local HVM
guests with access to memory mapped I/O regions to cause a
denial of service (CPU consumption and possibly hypervisor
or guest kernel panic) via a crafted GFN range. (bnc#831120)

XSA-58: CVE-2013-1918: Certain page table manipulation
operations in Xen 4.1.x, 4.2.x, and earlier are not
preemptible, which allows local PV kernels to cause a denial
of service via vectors related to 'deep page table
traversal.' (bnc#826882)

XSA-58: CVE-2013-1432: Xen 4.1.x and 4.2.x, when the XSA-45
patch is in place, does not properly maintain references on
pages stored for deferred cleanup, which allows local PV
guest kernels to cause a denial of service (premature page
free and hypervisor crash) or possible gain privileges via
unspecified vectors. (bnc#826882)

XSA-57: CVE-2013-2211: The libxenlight (libxl) toolstack
library in Xen 4.0.x, 4.1.x, and 4.2.x uses weak permissions
for xenstore keys for paravirtualised and emulated serial
console devices, which allows local guest administrators to
modify the xenstore value via unspecified vectors.
(bnc#823608)

XSA-56: CVE-2013-2072: Buffer overflow in the Python
bindings for the xc_vcpu_setaffinity call in Xen 4.0.x,
4.1.x, and 4.2.x allows local administrators with
permissions to configure VCPU affinity to cause a denial of
service (memory corruption and xend toolstack crash) and
possibly gain privileges via a crafted cpumap. (bnc#819416)

XSA-55: CVE-2013-2196: Multiple unspecified vulnerabilities
in the Elf parser (libelf) in Xen 4.2.x and earlier allow
local guest administrators with certain permissions to have
an unspecified impact via a crafted kernel, related to
'other problems' that are not CVE-2013-2194 or
CVE-2013-2195. (bnc#823011)

XSA-55: CVE-2013-2195: The Elf parser (libelf) in Xen 4.2.x
and earlier allow local guest administrators with certain
permissions to have an unspecified impact via a crafted
kernel, related to 'pointer dereferences' involving
unexpected calculations. (bnc#823011)

XSA-55: CVE-2013-2194: Multiple integer overflows in the Elf
parser (libelf) in Xen 4.2.x and earlier allow local guest
administrators with certain permissions to have an
unspecified impact via a crafted kernel. (bnc#823011)

XSA-53: CVE-2013-2077: Xen 4.0.x, 4.1.x, and 4.2.x does not
properly restrict the contents of a XRSTOR, which allows
local PV guest users to cause a denial of service (unhandled
exception and hypervisor crash) via unspecified vectors.
(bnc#820919)

XSA-52: CVE-2013-2076: Xen 4.0.x, 4.1.x, and 4.2.x, when
running on AMD64 processors, only save/restore the FOP, FIP,
and FDP x87 registers in FXSAVE/FXRSTOR when an exception is
pending, which allows one domain to determine portions of
the state of floating point instructions of other domains,
which can be leveraged to obtain sensitive information such
as cryptographic keys, a similar vulnerability to
CVE-2006-1056. NOTE: this is the documented behavior of
AMD64 processors, but it is inconsistent with Intel
processors in a security-relevant fashion that was not
addressed by the kernels. (bnc#820917)

XSA-50: CVE-2013-1964: Xen 4.0.x and 4.1.x incorrectly
releases a grant reference when releasing a non-v1,
non-transitive grant, which allows local guest
administrators to cause a denial of service (host crash),
obtain sensitive information, or possible have other impacts
via unspecified vectors. (bnc#816156)

XSA-49: CVE-2013-1952: Xen 4.x, when using Intel VT-d for a
bus mastering capable PCI device, does not properly check
the source when accessing a bridge device's interrupt
remapping table entries for MSI interrupts, which allows
local guest domains to cause a denial of service (interrupt
injection) via unspecified vectors. (bnc#816163)

XSA-47: CVE-2013-1920: Xen 4.2.x, 4.1.x, and earlier, when
the hypervisor is running 'under memory pressure' and the
Xen Security Module (XSM) is enabled, uses the wrong
ordering of operations when extending the per-domain event
channel tracking table, which causes a use-after-free and
allows local guest kernels to inject arbitrary events and
gain privileges via unspecified vectors. (bnc#813677)

XSA-46: CVE-2013-1919: Xen 4.2.x and 4.1.x does not properly
restrict access to IRQs, which allows local stub domain
clients to gain access to IRQs and cause a denial of service
via vectors related to 'passed-through IRQs or PCI devices.'
(bnc#813675)

XSA-45: CVE-2013-1918: Certain page table manipulation
operations in Xen 4.1.x, 4.2.x, and earlier are not
preemptible, which allows local PV kernels to cause a denial
of service via vectors related to 'deep page table
traversal.' (bnc#816159)

XSA-44: CVE-2013-1917: Xen 3.1 through 4.x, when running
64-bit hosts on Intel CPUs, does not clear the NT flag when
using an IRET after a SYSENTER instruction, which allows PV
guest users to cause a denial of service (hypervisor crash)
by triggering a #GP fault, which is not properly handled by
another IRET instruction. (bnc#813673)

XSA-41: CVE-2012-6075: Buffer overflow in the e1000_receive
function in the e1000 device driver (hw/e1000.c) in QEMU
1.3.0-rc2 and other versions, when the SBP and LPE flags are
disabled, allows remote attackers to cause a denial of
service (guest OS crash) and possibly execute arbitrary
guest code via a large packet. (bnc#797523)

XSA-37: CVE-2013-0154: The get_page_type function in
xen/arch/x86/mm.c in Xen 4.2, when debugging is enabled,
allows local PV or HVM guest administrators to cause a
denial of service (assertion failure and hypervisor crash)
via unspecified vectors related to a hypercall. (bnc#797031)

XSA-36: CVE-2013-0153: The AMD IOMMU support in Xen 4.2.x,
4.1.x, 3.3, and other versions, when using AMD-Vi for PCI
passthrough, uses the same interrupt remapping table for the
host and all guests, which allows guests to cause a denial
of service by injecting an interrupt into other guests.
(bnc#800275)

XSA-33: CVE-2012-5634: Xen 4.2.x, 4.1.x, and 4.0, when using
Intel VT-d for PCI passthrough, does not properly configure
VT-d when supporting a device that is behind a legacy PCI
Bridge, which allows local guests to cause a denial of
service to other guests by injecting an interrupt.
(bnc#794316)

XSA-31: CVE-2012-5515: The (1) XENMEM_decrease_reservation,
(2) XENMEM_populate_physmap, and (3) XENMEM_exchange
hypercalls in Xen 4.2 and earlier allow local guest
administrators to cause a denial of service (long loop and
hang) via a crafted extent_order value. (bnc#789950)

XSA-30: CVE-2012-5514: The
guest_physmap_mark_populate_on_demand function in Xen 4.2
and earlier does not properly unlock the subject GFNs when
checking if they are in use, which allows local guest HVM
administrators to cause a denial of service (hang) via
unspecified vectors. (bnc#789948)

XSA-29: CVE-2012-5513: The XENMEM_exchange handler in Xen
4.2 and earlier does not properly check the memory address,
which allows local PV guest OS administrators to cause a
denial of service (crash) or possibly gain privileges via
unspecified vectors that overwrite memory in the hypervisor
reserved range. (bnc#789951)

XSA-27: CVE-2012-6333: Multiple HVM control operations in
Xen 3.4 through 4.2 allow local HVM guest OS administrators
to cause a denial of service (physical CPU consumption) via
a large input. (bnc#789944)

XSA-27: CVE-2012-5511: Stack-based buffer overflow in the
dirty video RAM tracking functionality in Xen 3.4 through
4.1 allows local HVM guest OS administrators to cause a
denial of service (crash) via a large bitmap image.
(bnc#789944)

XSA-26: CVE-2012-5510: Xen 4.x, when downgrading the grant
table version, does not properly remove the status page from
the tracking list when freeing the page, which allows local
guest OS administrators to cause a denial of service
(hypervisor crash) via unspecified vectors. (bnc#789945)

XSA-25: CVE-2012-4544: The PV domain builder in Xen 4.2 and
earlier does not validate the size of the kernel or ramdisk
(1) before or (2) after decompression, which allows local
guest administrators to cause a denial of service (domain 0
memory consumption) via a crafted (a) kernel or (b) ramdisk.
(bnc#787163)

XSA-24: CVE-2012-4539: Xen 4.0 through 4.2, when running
32-bit x86 PV guests on 64-bit hypervisors, allows local
guest OS administrators to cause a denial of service
(infinite loop and hang or crash) via invalid arguments to
GNTTABOP_get_status_frames, aka 'Grant table hypercall
infinite loop DoS vulnerability.' (bnc#786520)

XSA-23: CVE-2012-4538: The HVMOP_pagetable_dying hypercall
in Xen 4.0, 4.1, and 4.2 does not properly check the
pagetable state when running on shadow pagetables, which
allows a local HVM guest OS to cause a denial of service
(hypervisor crash) via unspecified vectors. (bnc#786519)

XSA-22: CVE-2012-4537: Xen 3.4 through 4.2, and possibly
earlier versions, does not properly synchronize the p2m and
m2p tables when the set_p2m_entry function fails, which
allows local HVM guest OS administrators to cause a denial
of service (memory consumption and assertion failure), aka
'Memory mapping failure DoS vulnerability.' (bnc#786517)

XSA-20: CVE-2012-4535: Xen 3.4 through 4.2, and possibly
earlier versions, allows local guest OS administrators to
cause a denial of service (Xen infinite loop and physical
CPU consumption) by setting a VCPU with an 'inappropriate
deadline.' (bnc#786516)

XSA-19: CVE-2012-4411: The graphical console in Xen 4.0, 4.1
and 4.2 allows local OS guest administrators to obtain
sensitive host resource information via the qemu monitor.
NOTE: this might be a duplicate of CVE-2007-0998.
(bnc#779212)

XSA-15: CVE-2012-3497: (1) TMEMC_SAVE_GET_CLIENT_WEIGHT, (2)
TMEMC_SAVE_GET_CLIENT_CAP, (3) TMEMC_SAVE_GET_CLIENT_FLAGS
and (4) TMEMC_SAVE_END in the Transcendent Memory (TMEM) in
Xen 4.0, 4.1, and 4.2 allow local guest OS users to cause a
denial of service (NULL pointer dereference or memory
corruption and host crash) or possibly have other
unspecified impacts via a NULL client id. (bnc#777890)

Also the following non-security bugs have been fixed :

  - xen hot plug attach/detach fails modified
    blktap-pv-cdrom.patch. (bnc#805094)

  - guest 'disappears' after live migration Updated
    block-dmmd script. (bnc#777628)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=d46197780129fa94fee1eb1708143171
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b3fed2ec"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-1056.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-0998.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3497.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4411.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4535.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4537.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4538.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4539.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4544.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5510.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5511.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5513.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5514.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5515.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5634.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-6075.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-6333.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0153.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0154.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1432.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1442.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1917.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1918.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1919.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1920.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1952.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1964.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2072.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2076.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2077.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2194.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2195.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2196.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2211.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2212.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4329.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4355.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4361.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4368.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4494.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4553.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4554.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6885.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1891.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1892.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1893.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1894.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/777628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/777890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/779212"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/786516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/786517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/786519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/786520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/787163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/789944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/789945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/789948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/789950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/789951"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/794316"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/797031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/797523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/800275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/805094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/813673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/813675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/813677"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/816156"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/816159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/816163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/819416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/820917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/820919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/823011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/823608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/826882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/831120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/839596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/839618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/840592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/841766"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/842511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/848657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/849667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/849668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/853049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/860163"
  );
  # https://www.suse.com/support/update/announcement/2014/suse-su-20140446-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e4176238"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11 SP1 LTSS :

zypper in -t patch slessp1-xen-201402-8963

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^1$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-4.0.3_21548_16-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-doc-html-4.0.3_21548_16-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-doc-pdf-4.0.3_21548_16-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-kmp-default-4.0.3_21548_16_2.6.32.59_0.9-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-kmp-trace-4.0.3_21548_16_2.6.32.59_0.9-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-libs-4.0.3_21548_16-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-tools-4.0.3_21548_16-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-tools-domU-4.0.3_21548_16-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-kmp-pae-4.0.3_21548_16_2.6.32.59_0.9-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-4.0.3_21548_16-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-doc-html-4.0.3_21548_16-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-doc-pdf-4.0.3_21548_16-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-kmp-default-4.0.3_21548_16_2.6.32.59_0.9-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-kmp-trace-4.0.3_21548_16_2.6.32.59_0.9-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-libs-4.0.3_21548_16-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-tools-4.0.3_21548_16-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-tools-domU-4.0.3_21548_16-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-kmp-pae-4.0.3_21548_16_2.6.32.59_0.9-0.5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Xen");
}
