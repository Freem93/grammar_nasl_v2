#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2012-0056.
#

include("compat.inc");

if (description)
{
  script_id(79490);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2012-5510", "CVE-2012-5511", "CVE-2012-5513", "CVE-2012-5514", "CVE-2012-5515");
  script_bugtraq_id(56794, 56796, 56797, 56798, 56803);

  script_name(english:"OracleVM 3.0 : xen (OVMSA-2012-0056)");
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

  - xen: fix error handling of
    guest_physmap_mark_populate_on_demand The only user of
    the 'out' label bypasses a necessary unlock, thus
    enabling the caller to lock up Xen. Also, the function
    was never meant to be called by a guest for itself, so
    rather than inspecting the code paths in depth for
    potential other problems this might cause, and adjusting
    e.g. the non-guest printk in the above error path, just
    disallow the guest access to it. Finally, the printk
    (considering its potential of spamming the log, the more
    that it's not using XENLOG_GUEST), is being converted to
    P2M_DEBUG, as debugging is what it apparently was added
    for in the first place. This is XSA-30 / CVE-2012-5514.
    (CVE-2012-5514)

  - Revert version 2 of XSA-30 / CVE-2012-5514
    (CVE-2012-5514)

  - memop: limit guest specified extent order Allowing
    unbounded order values here causes almost unbounded
    loops and/or partially incomplete requests, particularly
    in PoD code. The added range checks in populate_physmap,
    decrease_reservation, and the 'in' one in
    memory_exchange architecturally all could use PADDR_BITS
    - PAGE_SHIFT, and are being artificially constrained to
    MAX_ORDER. This is XSA-31 / CVE-2012-5515.
    (CVE-2012-5515)

  - xen: fix error path of
    guest_physmap_mark_populate_on_demand The only user of
    the 'out' label bypasses a necessary unlock, thus
    enabling the caller to lock up Xen. This is XSA-30 /
    CVE-2012-5514. (CVE-2012-5514)

  - xen: add missing guest address range checks to
    XENMEM_exchange handlers Ever since its existence (3.0.3
    iirc) the handler for this has been using non address
    range checking guest memory accessors (i.e. the ones
    prefixed with two underscores) without first range
    checking the accessed space (via guest_handle_okay),
    allowing a guest to access and overwrite hypervisor
    memory. This is XSA-29 / CVE-2012-5513.

  - hvm: Limit the size of large HVM op batches Doing large
    p2m updates for HVMOP_track_dirty_vram without
    preemption ties up the physical processor. Integrating
    preemption into the p2m updates is hard so simply limit
    to 1GB which is sufficient for a 15000 * 15000 * 32bpp
    framebuffer. For HVMOP_modified_memory and
    HVMOP_set_mem_type preemptible add the necessary
    machinery to handle preemption. This is CVE-2012-5511 /
    XSA-27.

    x86/paging: Don't allocate user-controlled amounts of
    stack memory. This is XSA-27 / CVE-2012-5511.

    v2: Provide definition of GB to fix x86-32 compile.

  - xen/common/grant_table.c gnttab: fix releasing of memory
    upon switches between versions
    gnttab_unpopulate_status_frames incompletely freed the
    pages previously used as status frame in that they did
    not get removed from the domain's xenpage_list, thus
    causing subsequent list corruption when those pages did
    get allocated again for the same or another purpose.
    Similarly, grant_table_create and gnttab_grow_table both
    improperly clean up in the event of an error - pages
    already shared with the guest can't be freed by just
    passing them to free_xenheap_page. Fix this by sharing
    the pages only after all allocations succeeded. This is
    CVE-2012-5510 / XSA-26. (CVE-2012-5510)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2012-December/000113.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7261a1be"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-devel / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/05");
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
if (! ereg(pattern:"^OVS" + "3\.0" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.0", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.0", reference:"xen-4.0.0-81.el5.25")) flag++;
if (rpm_check(release:"OVS3.0", reference:"xen-devel-4.0.0-81.el5.25")) flag++;
if (rpm_check(release:"OVS3.0", reference:"xen-tools-4.0.0-81.el5.25")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-devel / xen-tools");
}
