#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60834);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2010-1084", "CVE-2010-2066", "CVE-2010-2070", "CVE-2010-2226", "CVE-2010-2248", "CVE-2010-2521", "CVE-2010-2524");

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
"This update fixes the following security issues :

  - instances of unsafe sprintf() use were found in the
    Linux kernel Bluetooth implementation. Creating a large
    number of Bluetooth L2CAP, SCO, or RFCOMM sockets could
    result in arbitrary memory pages being overwritten. A
    local, unprivileged user could use this flaw to cause a
    kernel panic (denial of service) or escalate their
    privileges. (CVE-2010-1084, Important)

  - a flaw was found in the Xen hypervisor implementation
    when using the Intel Itanium architecture, allowing
    guests to enter an unsupported state. An unprivileged
    guest user could trigger this flaw by setting the BE
    (Big Endian) bit of the Processor Status Register (PSR),
    leading to the guest crashing (denial of service).
    (CVE-2010-2070, Important)

  - a flaw was found in the CIFSSMBWrite() function in the
    Linux kernel Common Internet File System (CIFS)
    implementation. A remote attacker could send a specially
    crafted SMB response packet to a target CIFS client,
    resulting in a kernel panic (denial of service).
    (CVE-2010-2248, Important)

  - buffer overflow flaws were found in the Linux kernel's
    implementation of the server-side External Data
    Representation (XDR) for the Network File System (NFS)
    version 4. An attacker on the local network could send a
    specially crafted large compound request to the NFSv4
    server, which could possibly result in a kernel panic
    (denial of service) or, potentially, code execution.
    (CVE-2010-2521, Important)

  - a flaw was found in the handling of the SWAPEXT IOCTL in
    the Linux kernel XFS file system implementation. A local
    user could use this flaw to read write-only files, that
    they do not own, on an XFS file system. This could lead
    to unintended information disclosure. (CVE-2010-2226,
    Moderate)

  - a flaw was found in the dns_resolver upcall used by
    CIFS. A local, unprivileged user could redirect a
    Microsoft Distributed File System link to another IP
    address, tricking the client into mounting the share
    from a server of the user's choosing. (CVE-2010-2524,
    Moderate)

  - a missing check was found in the mext_check_arguments()
    function in the ext4 file system code. A local user
    could use this flaw to cause the MOVE_EXT IOCTL to
    overwrite the contents of an append-only file on an ext4
    file system, if they have write permissions for that
    file. (CVE-2010-2066, Low)

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1008&L=scientific-linux-errata&T=0&P=1311
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6083e1f4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-194.11.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-194.11.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-194.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-194.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-194.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-194.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-194.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-194.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-194.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-194.11.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
