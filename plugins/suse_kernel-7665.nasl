#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(59158);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/05/17 14:34:35 $");

  script_cve_id("CVE-2011-0726", "CVE-2011-1017", "CVE-2011-1093", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1585", "CVE-2011-1593", "CVE-2011-1745", "CVE-2011-1746", "CVE-2011-2022", "CVE-2011-2182", "CVE-2011-2484", "CVE-2011-2491", "CVE-2011-2496");

  script_name(english:"SuSE 10 Security Update : Linux kernel (ZYPP Patch Number 7665)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update for the SUSE Linux Enterprise 10 SP4 kernel fixes
several security issues and bugs.

The following security issues were fixed :

  - The dccp_rcv_state_process function in net/dccp/input.c
    in the Datagram Congestion Control Protocol (DCCP)
    implementation in the Linux kernel did not properly
    handle packets for a CLOSED endpoint, which allowed
    remote attackers to cause a denial of service (NULL
    pointer dereference and OOPS) by sending a DCCP-Close
    packet followed by a DCCP-Reset packet. (CVE-2011-1093)

  - The add_del_listener function in kernel/taskstats.c in
    the Linux kernel did not prevent multiple registrations
    of exit handlers, which allowed local users to cause a
    denial of service (memory and CPU consumption), and
    bypass the OOM Killer, via a crafted application.
    (CVE-2011-2484)

  - Integer overflow in the agp_generic_insert_memory
    function in drivers/char/agp/generic.c in the Linux
    kernel allowed local users to gain privileges or cause a
    denial of service (system crash) via a crafted
    AGPIOC_BIND agp_ioctl ioctl call. (CVE-2011-1745)

  - Multiple integer overflows in the (1)
    agp_allocate_memory and (2) agp_create_user_memory
    functions in drivers/char/agp/generic.c in the Linux
    kernel allowed local users to trigger buffer overflows,
    and consequently cause a denial of service (system
    crash) or possibly have unspecified other impact, via
    vectors related to calls that specify a large number of
    memory pages. (CVE-2011-1746)

  - The agp_generic_remove_memory function in
    drivers/char/agp/generic.c in the Linux kernel before
    2.6.38.5 did not validate a certain start parameter,
    which allowed local users to gain privileges or cause a
    denial of service (system crash) via a crafted
    AGPIOC_UNBIND agp_ioctl ioctl call, a different
    vulnerability than CVE-2011-1745. (CVE-2011-2022)

  - When using a setuid root mount.cifs, local users could
    hijack password protected mounted CIFS shares of other
    local users. (CVE-2011-1585)

  - The do_task_stat function in fs/proc/array.c in the
    Linux kernel did not perform an expected uid check,
    which made it easier for local users to defeat the ASLR
    protection mechanism by reading the start_code and
    end_code fields in the /proc/#####/stat file for a
    process executing a PIE binary. (CVE-2011-0726)

  - The normal mmap paths all avoid creating a mapping where
    the pgoff inside the mapping could wrap around due to
    overflow. However, an expanding mremap() can take such a
    non-wrapping mapping and make it bigger and cause a
    wrapping condition. (CVE-2011-2496)

  - A local unprivileged user able to access a NFS
    filesystem could use file locking to deadlock parts of
    an nfs server under some circumstance. (CVE-2011-2491)

  - The code for evaluating LDM partitions (in
    fs/partitions/ldm.c) contained bugs that could crash the
    kernel for certain corrupted LDM partitions.
    (CVE-2011-1017 / CVE-2011-2182)

  - Multiple integer overflows in the next_pidmap function
    in kernel/pid.c in the Linux kernel allowed local users
    to cause a denial of service (system crash) via a
    crafted (1) getdents or (2) readdir system call.
    (CVE-2011-1593)

  - Integer overflow in the _ctl_do_mpt_command function in
    drivers/scsi/mpt2sas/mpt2sas_ctl.c in the Linux kernel
    might have allowed local users to gain privileges or
    cause a denial of service (memory corruption) via an
    ioctl call specifying a crafted value that triggers a
    heap-based buffer overflow. (CVE-2011-1494)

  - drivers/scsi/mpt2sas/mpt2sas_ctl.c in the Linux kernel
    did not validate (1) length and (2) offset values before
    performing memory copy operations, which might have
    allowed local users to gain privileges, cause a denial
    of service (memory corruption), or obtain sensitive
    information from kernel memory via a crafted ioctl call,
    related to the _ctl_do_mpt_command and
    _ctl_diag_read_buffer functions. (CVE-2011-1495)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0726.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1017.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1093.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1494.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1495.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1585.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1593.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1745.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1746.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2022.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2182.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2484.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2491.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2496.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7665.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.89.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.89.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.89.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.89.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.89.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-debug-2.6.16.60-0.89.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.89.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-kdump-2.6.16.60-0.89.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.89.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.89.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.89.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.89.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
