#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2013-0085.
#

include("compat.inc");

if (description)
{
  script_id(79523);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2013-4494", "CVE-2013-4553", "CVE-2013-4554");
  script_bugtraq_id(63494, 63931, 63933);

  script_name(english:"OracleVM 3.2 : xen (OVMSA-2013-0085)");
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

  - x86/HVM: only allow ring 0 guest code to make hypercalls
    Anything else would allow for privilege escalation. This
    is CVE-2013-4554 / XSA-76. (CVE-2013-4554)

  - x86: restrict XEN_DOMCTL_getmemlist Coverity ID 1055652
    (See the code comment.) This is CVE-2013-4553 / XSA-74.
    (CVE-2013-4553)

  - gnttab: update version 1 of xsa73-4.1.patch to version 3
    Version 1 of xsa73-4.1.patch had an error: bool_t
    drop_dom_ref = (e->tot_pages-- == 0)  should have been:
    bool_t drop_dom_ref = (e->tot_pages-- == 1) 

    Consolidate error handling.

    Backported to Xen-4.1 (CVE-2013-4494)

  - Xen: Spread boot time page scrubbing across all
    available CPU's Written by Malcolm Crossley The page
    scrubbing is done in 256MB chunks in lockstep across all
    the CPU's. This allows for the boot CPU to hold the
    heap_lock whilst each chunk is being scrubbed and then
    release the heap_lock when all CPU's are finished
    scrubing their individual chunk. This allows for the
    heap_lock to not be held continously and for pending
    softirqs are to be serviced periodically across all
    CPU's. The page scrub memory chunks are allocated to the
    CPU's in a NUMA aware fashion to reduce Socket
    interconnect overhead and improve performance. This
    patch reduces the boot page scrub time on a 256GB 16
    core AMD Opteron machine from 1 minute 46 seconds to 38
    seconds.

  - gnttab: correct locking order reversal Coverity ID
    1087189 Correct a lock order reversal between a domains
    page allocation and grant table locks. This is XSA-73.

    Consolidate error handling.

    Backported to Xen-4.1 (CVE-2013-4494)

  - piix4acpi, xen, hotplug: Fix race with ACPI AML code and
    hotplug. This is a race so the amount varies but on a
    4PCPU box I seem to get only ~14 out of 16 vCPUs I want
    to online. The issue at hand is that QEMU xenstore.c
    hotplug code changes the vCPU array and triggers an ACPI
    SCI for each vCPU online/offline change. That means we
    modify the array of vCPUs as the guests ACPI AML code is
    reading it - resulting in the guest reading the data
    only once and not changing the CPU states appropiately.
    The fix is to seperate the vCPU array changes from the
    ACPI SCI notification. The code now will enumerate all
    of the vCPUs and change the vCPU array if there is a
    need for a change. If a change did occur then only _one_
    ACPI SCI pulse is sent to the guest. The vCPU array at
    that point has the online/offline modified to what the
    user wanted to have.

    [v1: Use stack for the 'attr' instead of malloc/free]

  - piix4acpi, xen: Clarify that the qemu_set_irq calls just
    do an IRQ pulse. The 'qemu_cpu_notify' raises and lowers
    the ACPI SCI line when the vCPU state has changed.
    Instead of doing the two functions, just use one
    function that describes exactly what it does.

  - piix4acpi, xen, vcpu hotplug: Split the notification
    from the changes. This is a prepatory patch that splits
    the notification of an vCPU change from the actual
    changes to the vCPU array.

  - Backported Carson's changes - Requests to connect on
    port 8003 with a LOW/weak cipher are now rejected."
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2013-December/000196.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d8768268"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-devel / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/06");
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
if (! ereg(pattern:"^OVS" + "3\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.2", reference:"xen-4.1.3-25.el5.88")) flag++;
if (rpm_check(release:"OVS3.2", reference:"xen-devel-4.1.3-25.el5.88")) flag++;
if (rpm_check(release:"OVS3.2", reference:"xen-tools-4.1.3-25.el5.88")) flag++;

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
