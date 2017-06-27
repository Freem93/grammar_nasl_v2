#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60477);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2007-6417", "CVE-2007-6716", "CVE-2008-2931", "CVE-2008-3272", "CVE-2008-3275");

  script_name(english:"Scientific Linux Security Update : kernel on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security fixes :

  - a missing capability check was found in the Linux kernel
    do_change_type routine. This could allow a local
    unprivileged user to gain privileged access or cause a
    denial of service. (CVE-2008-2931, Important)

  - a flaw was found in the Linux kernel Direct-IO
    implementation. This could allow a local unprivileged
    user to cause a denial of service. (CVE-2007-6716,
    Important)

  - Tobias Klein reported a missing check in the Linux
    kernel Open Sound System (OSS) implementation. This
    deficiency could lead to a possible information leak.
    (CVE-2008-3272, Moderate)

  - a deficiency was found in the Linux kernel virtual
    filesystem (VFS) implementation. This could allow a
    local unprivileged user to attempt file creation within
    deleted directories, possibly causing a denial of
    service. (CVE-2008-3275, Moderate)

  - a flaw was found in the Linux kernel tmpfs
    implementation. This could allow a local unprivileged
    user to read sensitive information from the kernel.
    (CVE-2007-6417, Moderate)

Bug fixes :

  - when copying a small IPoIB packet from the original skb
    it was received in to a new, smaller skb, all fields in
    the new skb were not initialized. This may have caused a
    kernel oops.

  - previously, data may have been written beyond the end of
    an array, causing memory corruption on certain systems,
    resulting in hypervisor crashes during context
    switching.

  - a kernel crash may have occurred on heavily-used Samba
    servers after 24 to 48 hours of use.

  - under heavy memory pressure, pages may have been swapped
    out from under the SGI Altix XPMEM driver, causing
    silent data corruption in the kernel.

  - the ixgbe driver is untested, but support was advertised
    for the Intel 82598 network card. If this card was
    present when the ixgbe driver was loaded, a NULL pointer
    dereference and a panic occurred.

  - on certain systems, if multiple InfiniBand queue pairs
    simultaneously fell into an error state, an overrun may
    have occurred, stopping traffic.

  - with bridging, when forward delay was set to zero,
    setting an interface to the forwarding state was delayed
    by one or possibly two timers, depending on whether STP
    was enabled. This may have caused long delays in moving
    an interface to the forwarding state. This issue caused
    packet loss when migrating virtual machines, preventing
    them from being migrated without interrupting
    applications.

  - on certain multinode systems, IPMI device nodes were
    created in reverse order of where they physically
    resided.

  - process hangs may have occurred while accessing
    application data files via asynchronous direct I/O
    system calls.

  - on systems with heavy lock traffic, a possible deadlock
    may have caused anything requiring locks over NFS to
    stop, or be very slow. Errors such as 'lockd: server
    [IP] not responding, timed out' were logged on client
    systems.

  - unexpected removals of USB devices may have caused a
    NULL pointer dereference in kobject_get_path.

  - on Itanium-based systems, repeatedly creating and
    destroying Windows guests may have caused Dom0 to crash,
    due to the 'XENMEM_add_to_physmap' hypercall, used by
    para-virtualized drivers on HVM, being SMP-unsafe.

  - when using an MD software RAID, crashes may have
    occurred when devices were removed or changed while
    being iterated through. Correct locking is now used.

  - break requests had no effect when using 'Serial Over
    Lan' with the Intel 82571 network card. This issue may
    have caused log in problems.

  - on Itanium-based systems, module_free() referred the
    first parameter before checking it was valid. This may
    have caused a kernel panic when exiting SystemTap."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0809&L=scientific-linux-errata&T=0&P=805
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb4a2be0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(189, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-92.1.13.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-92.1.13.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-92.1.13.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-92.1.13.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-92.1.13.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-92.1.13.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-92.1.13.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kernel-headers-2.6.18-92.1.13.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-92.1.13.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-92.1.13.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
