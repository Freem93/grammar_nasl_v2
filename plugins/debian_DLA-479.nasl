#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-479-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(91198);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/06 20:03:51 $");

  script_cve_id("CVE-2015-2752", "CVE-2015-2756", "CVE-2015-5165", "CVE-2015-5307", "CVE-2015-7969", "CVE-2015-7970", "CVE-2015-7971", "CVE-2015-7972", "CVE-2015-8104", "CVE-2015-8339", "CVE-2015-8340", "CVE-2015-8550", "CVE-2015-8554", "CVE-2015-8555", "CVE-2015-8615", "CVE-2016-1570", "CVE-2016-1571", "CVE-2016-2270", "CVE-2016-2271");
  script_bugtraq_id(72577, 73448);
  script_osvdb_id(120061, 120062, 125706, 129598, 129599, 129600, 129601, 130089, 130090, 131284, 131285, 132029, 132032, 132050, 132098, 133503, 133504, 134693, 134694);

  script_name(english:"Debian DLA-479-1 : xen security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This security update fixes a number of security issues in Xen in
wheezy.

For Debian 7 'Wheezy', these problems have been fixed in version
4.1.6.1-1+deb7u1.

We recommend that you upgrade your libidn packages.

CVE-2015-2752

The XEN_DOMCTL_memory_mapping hypercall in Xen 3.2.x through 4.5.x,
when using a PCI passthrough device, is not preemptable, which allows
local x86 HVM domain users to cause a denial of service (host CPU
consumption) via a crafted request to the device model (qemu-dm).

CVE-2015-2756

QEMU, as used in Xen 3.3.x through 4.5.x, does not properly restrict
access to PCI command registers, which might allow local HVM guest
users to cause a denial of service (non-maskable interrupt and host
crash) by disabling the (1) memory or (2) I/O decoding for a PCI
Express device and then accessing the device, which triggers an
Unsupported Request (UR) response.

CVE-2015-5165

The C+ mode offload emulation in the RTL8139 network card device model
in QEMU, as used in Xen 4.5.x and earlier, allows remote attackers to
read process heap memory via unspecified vectors.

CVE-2015-5307

The KVM subsystem in the Linux kernel through 4.2.6, and Xen 4.3.x
through 4.6.x, allows guest OS users to cause a denial of service
(host OS panic or hang) by triggering many #AC (aka Alignment Check)
exceptions, related to svm.c and vmx.c.

CVE-2015-7969

Multiple memory leaks in Xen 4.0 through 4.6.x allow local guest
administrators or domains with certain permission to cause a denial of
service (memory consumption) via a large number of 'teardowns' of
domains with the vcpu pointer array allocated using the (1)
XEN_DOMCTL_max_vcpus hypercall or the xenoprofile state vcpu pointer
array allocated using the (2) XENOPROF_get_buffer or (3)
XENOPROF_set_passive hypercall.

CVE-2015-7970

The p2m_pod_emergency_sweep function in arch/x86/mm/p2m-pod.c in Xen
3.4.x, 3.5.x, and 3.6.x is not preemptible, which allows local x86 HVM
guest administrators to cause a denial of service (CPU consumption and
possibly reboot) via crafted memory contents that triggers a
'time-consuming linear scan,' related to Populate-on-Demand.

CVE-2015-7971

Xen 3.2.x through 4.6.x does not limit the number of printk console
messages when logging certain pmu and profiling hypercalls, which
allows local guests to cause a denial of service via a sequence of
crafted (1) HYPERCALL_xenoprof_op hypercalls, which are not properly
handled in the do_xenoprof_op function in common/xenoprof.c, or (2)
HYPERVISOR_xenpmu_op hypercalls, which are not properly handled in the
do_xenpmu_op function in arch/x86/cpu/vpmu.c.

CVE-2015-7972

The (1) libxl_set_memory_target function in tools/libxl/libxl.c and
(2) libxl__build_post function in tools/libxl/libxl_dom.c in Xen 3.4.x
through 4.6.x do not properly calculate the balloon size when using
the populate-on-demand (PoD) system, which allows local HVM guest
users to cause a denial of service (guest crash) via unspecified
vectors related to 'heavy memory pressure.'

CVE-2015-8104

The KVM subsystem in the Linux kernel through 4.2.6, and Xen 4.3.x
through 4.6.x, allows guest OS users to cause a denial of service
(host OS panic or hang) by triggering many #DB (aka Debug) exceptions,
related to svm.c.

CVE-2015-8339

The memory_exchange function in common/memory.c in Xen 3.2.x through
4.6.x does not properly hand back pages to a domain, which might allow
guest OS administrators to cause a denial of service (host crash) via
unspecified vectors related to domain teardown.

CVE-2015-8340

The memory_exchange function in common/memory.c in Xen 3.2.x through
4.6.x does not properly release locks, which might allow guest OS
administrators to cause a denial of service (deadlock or host crash)
via unspecified vectors, related to XENMEM_exchange error handling.

CVE-2015-8550

Xen, when used on a system providing PV backends, allows local guest
OS administrators to cause a denial of service (host OS crash) or gain
privileges by writing to memory shared between the frontend and
backend, aka a double fetch vulnerability.

CVE-2015-8554

Buffer overflow in hw/pt-msi.c in Xen 4.6.x and earlier, when using
the qemu-xen-traditional (aka qemu-dm) device model, allows local x86
HVM guest administrators to gain privileges by leveraging a system
with access to a passed-through MSI-X capable physical PCI device and
MSI-X table entries, related to a 'write path.'

CVE-2015-8555

Xen 4.6.x, 4.5.x, 4.4.x, 4.3.x, and earlier do not initialize x86 FPU
stack and XMM registers when XSAVE/XRSTOR are not used to manage guest
extended register state, which allows local guest domains to obtain
sensitive information from other domains via unspecified vectors.

CVE-2015-8615

The hvm_set_callback_via function in arch/x86/hvm/irq.c in Xen 4.6
does not limit the number of printk console messages when logging the
new callback method, which allows local HVM guest OS users to cause a
denial of service via a large number of changes to the callback method
(HVM_PARAM_CALLBACK_IRQ).

CVE-2016-1570

The PV superpage functionality in arch/x86/mm.c in Xen 3.4.0, 3.4.1,
and 4.1.x through 4.6.x allows local PV guests to obtain sensitive
information, cause a denial of service, gain privileges, or have
unspecified other impact via a crafted page identifier (MFN) to the
(1) MMUEXT_MARK_SUPER or (2) MMUEXT_UNMARK_SUPER sub-op in the
HYPERVISOR_mmuext_op hypercall or (3) unknown vectors related to page
table updates.

CVE-2016-1571

The paging_invlpg function in include/asm-x86/paging.h in Xen 3.3.x
through 4.6.x, when using shadow mode paging or nested virtualization
is enabled, allows local HVM guest users to cause a denial of service
(host crash) via a non-canonical guest address in an INVVPID
instruction, which triggers a hypervisor bug check.

CVE-2016-2270

Xen 4.6.x and earlier allows local guest administrators to cause a
denial of service (host reboot) via vectors related to multiple
mappings of MMIO pages with different cachability settings.

CVE-2016-2271

VMX in Xen 4.6.x and earlier, when using an Intel or Cyrix CPU, allows
local HVM guest users to cause a denial of service (guest crash) via
vectors related to a non-canonical RIP.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/05/msg00031.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/xen"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxen-4.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxen-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxen-ocaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxen-ocaml-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxenstore3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-docs-4.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-hypervisor-4.1-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-hypervisor-4.1-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-system-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-system-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-utils-4.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-utils-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xenstore-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"7.0", prefix:"libxen-4.1", reference:"4.1.6.1-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-dev", reference:"4.1.6.1-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-ocaml", reference:"4.1.6.1-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-ocaml-dev", reference:"4.1.6.1-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxenstore3.0", reference:"4.1.6.1-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"xen-docs-4.1", reference:"4.1.6.1-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"xen-hypervisor-4.1-amd64", reference:"4.1.6.1-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"xen-hypervisor-4.1-i386", reference:"4.1.6.1-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"xen-system-amd64", reference:"4.1.6.1-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"xen-system-i386", reference:"4.1.6.1-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"xen-utils-4.1", reference:"4.1.6.1-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"xen-utils-common", reference:"4.1.6.1-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"xenstore-utils", reference:"4.1.6.1-1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
