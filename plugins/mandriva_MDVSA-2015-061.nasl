#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:061. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(81944);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/19 15:24:54 $");

  script_cve_id("CVE-2013-4148", "CVE-2013-4149", "CVE-2013-4150", "CVE-2013-4151", "CVE-2013-4377", "CVE-2013-4526", "CVE-2013-4527", "CVE-2013-4529", "CVE-2013-4530", "CVE-2013-4531", "CVE-2013-4533", "CVE-2013-4534", "CVE-2013-4535", "CVE-2013-4536", "CVE-2013-4537", "CVE-2013-4538", "CVE-2013-4539", "CVE-2013-4540", "CVE-2013-4541", "CVE-2013-4542", "CVE-2013-6399", "CVE-2014-0142", "CVE-2014-0143", "CVE-2014-0144", "CVE-2014-0145", "CVE-2014-0146", "CVE-2014-0147", "CVE-2014-0148", "CVE-2014-0150", "CVE-2014-0182", "CVE-2014-0222", "CVE-2014-0223", "CVE-2014-3461", "CVE-2014-3615", "CVE-2014-3640", "CVE-2014-3689", "CVE-2014-5263", "CVE-2014-7815", "CVE-2014-7840", "CVE-2014-8106");
  script_xref(name:"MDVSA", value:"2015:061");

  script_name(english:"Mandriva Linux Security Advisory : qemu (MDVSA-2015:061)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated qemu packages fix multiple security vulnerabilities :

Sibiao Luo discovered that QEMU incorrectly handled device
hot-unplugging. A local user could possibly use this flaw to cause a
denial of service (CVE-2013-4377).

Michael S. Tsirkin discovered that QEMU incorrectly handled vmxnet3
devices. A local guest could possibly use this issue to cause a denial
of service, or possibly execute arbitrary code on the host
(CVE-2013-4544).

Multiple integer overflow, input validation, logic error, and buffer
overflow flaws were discovered in various QEMU block drivers. An
attacker able to modify a disk image file loaded by a guest could use
these flaws to crash the guest, or corrupt QEMU process memory on the
host, potentially resulting in arbitrary code execution on the host
with the privileges of the QEMU process (CVE-2014-0143, CVE-2014-0144,
CVE-2014-0145, CVE-2014-0147).

A buffer overflow flaw was found in the way the
virtio_net_handle_mac() function of QEMU processed guest requests to
update the table of MAC addresses. A privileged guest user could use
this flaw to corrupt QEMU process memory on the host, potentially
resulting in arbitrary code execution on the host with the privileges
of the QEMU process (CVE-2014-0150).

A divide-by-zero flaw was found in the seek_to_sector() function of
the parallels block driver in QEMU. An attacker able to modify a disk
image file loaded by a guest could use this flaw to crash the guest
(CVE-2014-0142).

A NULL pointer dereference flaw was found in the QCOW2 block driver in
QEMU. An attacker able to modify a disk image file loaded by a guest
could use this flaw to crash the guest (CVE-2014-0146).

It was found that the block driver for Hyper-V VHDX images did not
correctly calculate BAT (Block Allocation Table) entries due to a
missing bounds check. An attacker able to modify a disk image file
loaded by a guest could use this flaw to crash the guest
(CVE-2014-0148).

An out-of-bounds memory access flaw was found in the way QEMU's IDE
device driver handled the execution of SMART EXECUTE OFFLINE commands.
A privileged guest user could use this flaw to corrupt QEMU process
memory on the host, which could potentially result in arbitrary code
execution on the host with the privileges of the QEMU process
(CVE-2014-2894).

Two integer overflow flaws were found in the QEMU block driver for
QCOW version 1 disk images. A user able to alter the QEMU disk image
files loaded by a guest could use either of these flaws to corrupt
QEMU process memory on the host, which could potentially result in
arbitrary code execution on the host with the privileges of the QEMU
process (CVE-2014-0222, CVE-2014-0223).

Multiple buffer overflow, input validation, and out-of-bounds write
flaws were found in the way the virtio, virtio-net, virtio-scsi, and
usb drivers of QEMU handled state loading after migration. A user able
to alter the savevm data (either on the disk or over the wire during
migration) could use either of these flaws to corrupt QEMU process
memory on the (destination) host, which could potentially result in
arbitrary code execution on the host with the privileges of the QEMU
process (CVE-2013-4148, CVE-2013-4151, CVE-2013-4535, CVE-2013-4536,
CVE-2013-4541, CVE-2013-4542, CVE-2013-6399, CVE-2014-0182,
CVE-2014-3461).

An information leak flaw was found in the way QEMU's VGA emulator
accessed frame buffer memory for high resolution displays. A
privileged guest user could use this flaw to leak memory contents of
the host to the guest by setting the display to use a high resolution
in the guest (CVE-2014-3615).

When guest sends udp packet with source port and source addr 0,
uninitialized socket is picked up when looking for matching and
already created udp sockets, and later passed to sosendto() where NULL
pointer dereference is hit during so->slirp->vnetwork_mask.s_addr
access Only guests using qemu user networking are affected
(CVE-2014-3640).

The Advanced Threat Research team at Intel Security reported that
guest provided parameter were insufficiently validated in rectangle
functions in the vmware-vga driver. A privileged guest user could use
this flaw to write into qemu address space on the host, potentially
escalating their privileges to those of the qemu host process
(CVE-2014-3689).

It was discovered that QEMU incorrectly handled USB xHCI controller
live migration. An attacker could possibly use this issue to cause a
denial of service, or possibly execute arbitrary code (CVE-2014-5263).

James Spadaro of Cisco reported insufficiently sanitized
bits_per_pixel from the client in the QEMU VNC display driver. An
attacker having access to the guest's VNC console could use this flaw
to crash the guest (CVE-2014-7815).

During migration, the values read from migration stream during ram
load are not validated. Especially offset in host_from_stream_offset()
and also the length of the writes in the callers of the said function.
A user able to alter the savevm data (either on the disk or over the
wire during migration) could use either of these flaws to corrupt QEMU
process memory on the (destination) host, which could potentially
result in arbitrary code execution on the host with the privileges of
the QEMU process (CVE-2014-7840).

Paolo Bonzini of Red Hat discovered that the blit region checks were
insufficient in the Cirrus VGA emulator in qemu. A privileged guest
user could use this flaw to write into qemu address space on the host,
potentially escalating their privileges to those of the qemu host
process (CVE-2014-8106).

This update also provides usbredirparser 0.6 as a prerequisite of
qemu-1.6.2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0060.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0426.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0467.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0525.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64usbredirhost-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64usbredirhost1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64usbredirparser-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64usbredirparser1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:usbredir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:usbredir-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64usbredirhost-devel-0.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64usbredirhost1-0.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64usbredirparser-devel-0.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64usbredirparser1-0.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"qemu-1.6.2-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"qemu-img-1.6.2-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"usbredir-0.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"usbredir-devel-0.6-1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
