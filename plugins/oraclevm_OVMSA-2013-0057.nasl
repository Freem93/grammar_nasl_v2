#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2013-0057.
#

include("compat.inc");

if (description)
{
  script_id(79513);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2013-1432");
  script_bugtraq_id(60799);

  script_name(english:"OracleVM 3.1 : xen (OVMSA-2013-0057)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - x86: fix page refcount handling in page table pin error
    path In the original patch 7 of the series addressing
    XSA-45 I mistakenly took the addition of the call to
    get_page_light in alloc_page_type to cover two
    decrements that would happen: One for the PGT_partial
    bit that is getting set along with the call, and the
    other for the page reference the caller hold (and would
    be dropping on its error path). But of course the
    additional page reference is tied to the PGT_partial
    bit, and hence any caller of a function that may leave
    ->arch.old_guest_table non-NULL for error cleanup
    purposes has to make sure a respective page reference
    gets retained. Similar issues were then also spotted
    elsewhere: In effect all callers of
    get_page_type_preemptible need to deal with errors in
    similar ways. To make sure error handling can work this
    way without leaking page references, a respective
    assertion gets added to that function. This is
    CVE-2013-1432 / XSA-58.

  - libxl: Restrict permissions on PV console device
    xenstore nodes Matthew Daley has observed that the PV
    console protocol places sensitive host state into a
    guest writeable xenstore locations, this includes :

  - The pty used to communicate between the console backend
    daemon and its client, allowing the guest administrator
    to read and write arbitrary host files.

  - The output file, allowing the guest administrator to
    write arbitrary host files or to target arbitrary qemu
    chardevs which include sockets, udp, ptr, pipes etc (see
    -chardev in qemu(1) for a more complete list).

  - The maximum buffer size, allowing the guest
    administrator to consume more resources than the host
    administrator has configured.

  - The backend to use (qemu vs xenconsoled), potentially
    allowing the guest administrator to confuse host
    software. So we arrange to make the sensitive keys in
    the xenstore frontend directory read only for the guest.
    This is safe since the xenstore permissions model,
    unlike POSIX directory permissions, does not allow the
    guest to remove and recreate a node if it has write
    access to the containing directory. There are a few
    associated wrinkles :

  - The primary PV console is 'special'. It's xenstore node
    is not under the usual /devices/ subtree and it does not
    use the customary xenstore state machine protocol.
    Unfortunately its directory is used for other things,
    including the vnc-port node, which we do not want the
    guest to be able to write to. Rather than trying to
    track down all the possible secondary uses of this
    directory just make it r/o to the guest. All newly
    created subdirectories inherit these permissions and so
    are now safe by default.

  - The other serial consoles do use the customary xenstore
    state machine and therefore need write access to at
    least the 'protocol' and 'state' nodes, however they may
    also want to use arbitrary 'feature-foo' nodes (although
    I'm not aware of any) and therefore we cannot simply
    lock down the entire frontend directory. Instead we add
    support to libxl__device_generic_add for frontend keys
    which are explicitly read only and use that to lock down
    the sensitive keys.

  - Minios' console frontend wants to write the 'type' node,
    which it has no business doing since this is a
    host/toolstack level decision. This fails now that the
    node has become read only to the PV guest. Since the
    toolstack already writes this node just remove the
    attempt to set it. This is CVE-XXXX-XXX / XSA-57

    Conflicts (4.2 backport): tools/libxl/libxl.c (no vtpm,
    free front_ro on error in libxl__device_console_add)
    Conflicts (4.1 backport):
    extras/mini-os/console/xenbus.c tools/libxl/libxl.c
    tools/libxl/libxl_device.c tools/libxl/libxl_internal.h
    tools/libxl/libxl_pci.c tools/libxl/libxl_xshelp.c

  - minios code was in xencons_ring.c

  - many places need &gc not just gc

  - libxl__xs_writev path is not const

  - varios minor context fixups"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2013-June/000158.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-devel / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "3\.1" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.1", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.1", reference:"xen-4.1.2-18.el5.84")) flag++;
if (rpm_check(release:"OVS3.1", reference:"xen-devel-4.1.2-18.el5.84")) flag++;
if (rpm_check(release:"OVS3.1", reference:"xen-tools-4.1.2-18.el5.84")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-devel / xen-tools");
}
