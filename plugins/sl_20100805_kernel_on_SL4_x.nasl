#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60831);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2010-2248", "CVE-2010-2521");

  script_name(english:"Scientific Linux Security Update : kernel on SL4.x i386/x86_64");
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

This update also fixes the following bug :

  - the rpc_call_async() function in the SUN Remote
    Procedure Call (RPC) subsystem in the Linux kernel had a
    reference counting bug. In certain situations, some
    Network Lock Manager (NLM) messages may have triggered
    this bug on NFSv2 and NFSv3 servers, leading to a kernel
    panic (with 'kernel BUG at fs/lockd/host.c:[xxx]!'
    logged to '/var/log/messages'). (BZ#612962)

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1008&L=scientific-linux-errata&T=0&P=794
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?141205b0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=612962"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/05");
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
if (rpm_check(release:"SL4", reference:"kernel-2.6.9-89.0.28.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-devel-2.6.9-89.0.28.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-doc-2.6.9-89.0.28.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-2.6.9-89.0.28.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-89.0.28.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-89.0.28.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-89.0.28.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-2.6.9-89.0.28.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-devel-2.6.9-89.0.28.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-2.6.9-89.0.28.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-devel-2.6.9-89.0.28.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
