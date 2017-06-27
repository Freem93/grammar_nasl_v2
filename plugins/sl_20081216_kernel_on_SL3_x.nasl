#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60507);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2007-6063", "CVE-2008-0598", "CVE-2008-2136", "CVE-2008-2812", "CVE-2008-3275", "CVE-2008-3525", "CVE-2008-4210");

  script_name(english:"Scientific Linux Security Update : kernel on SL3.x i386/x86_64");
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
"This update addresses the following security issues :

  - Tavis Ormandy discovered a deficiency in the Linux
    kernel 32-bit and 64-bit emulation. This could allow a
    local, unprivileged user to prepare and run a specially
    crafted binary which would use this deficiency to leak
    uninitialized and potentially sensitive data.
    (CVE-2008-0598, Important)

  - a possible kernel memory leak was found in the Linux
    kernel Simple Internet Transition (SIT) INET6
    implementation. This could allow a local, unprivileged
    user to cause a denial of service. (CVE-2008-2136,
    Important)

  - missing capability checks were found in the SBNI WAN
    driver which could allow a local user to bypass intended
    capability restrictions. (CVE-2008-3525, Important)

  - the do_truncate() and generic_file_splice_write()
    functions did not clear the setuid and setgid bits. This
    could allow a local, unprivileged user to obtain access
    to privileged information. (CVE-2008-4210, Important)

  - a buffer overflow flaw was found in Integrated Services
    Digital Network (ISDN) subsystem. A local, unprivileged
    user could use this flaw to cause a denial of service.
    (CVE-2007-6063, Moderate)

  - multiple NULL pointer dereferences were found in various
    Linux kernel network drivers. These drivers were missing
    checks for terminal validity, which could allow
    privilege escalation. (CVE-2008-2812, Moderate)

  - a deficiency was found in the Linux kernel virtual
    filesystem (VFS) implementation. This could allow a
    local, unprivileged user to attempt file creation within
    deleted directories, possibly causing a denial of
    service. (CVE-2008-3275, Moderate)

This update also fixes the following bugs :

  - the incorrect kunmap function was used in
    nfs_xdr_readlinkres. kunmap() was used where
    kunmap_atomic() should have been. As a consequence, if
    an NFSv2 or NFSv3 server exported a volume containing a
    symlink which included a path equal to or longer than
    the local system's PATH_MAX, accessing the link caused a
    kernel oops. This has been corrected in this update.

  - mptctl_gettargetinfo did not check if pIoc3 was NULL
    before using it as a pointer. This caused a kernel panic
    in mptctl_gettargetinfo in some circumstances. A check
    has been added which prevents this.

  - lost tick compensation code in the timer interrupt
    routine triggered without apparent cause. When running
    as a fully-virtualized client, this spurious triggering
    caused the 64-bit version of Red Hat Enterprise Linux 3
    to present highly inaccurate times. With this update the
    lost tick compensation code is turned off when the
    operating system is running as a fully-virtualized
    client under Xen or VMware&reg;."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0812&L=scientific-linux-errata&T=0&P=1505
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d818bc13"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20, 119, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/16");
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
if (rpm_check(release:"SL3", reference:"kernel-2.4.21-58.EL")) flag++;
if (rpm_check(release:"SL3", cpu:"i386", reference:"kernel-BOOT-2.4.21-58.EL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-doc-2.4.21-58.EL")) flag++;
if (rpm_check(release:"SL3", cpu:"i386", reference:"kernel-hugemem-2.4.21-58.EL")) flag++;
if (rpm_check(release:"SL3", cpu:"i386", reference:"kernel-hugemem-unsupported-2.4.21-58.EL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-smp-2.4.21-58.EL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-smp-unsupported-2.4.21-58.EL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-source-2.4.21-58.EL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-unsupported-2.4.21-58.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
