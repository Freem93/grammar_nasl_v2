#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60335);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_cve_id("CVE-2007-4997", "CVE-2007-5494");

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
"A flaw was found in the handling of IEEE 802.11 frames, which affected
several wireless LAN modules. In certain situations, a remote attacker
could trigger this flaw by sending a malicious packet over a wireless
network, causing a denial of service (kernel crash). (CVE-2007-4997,
Important)

A memory leak was found in the Red Hat Content Accelerator kernel
patch. A local user could use this flaw to cause a denial of service
(memory exhaustion). (CVE-2007-5494, Important)

Additionally, the following bugs were fixed :

  - when running the 'ls -la' command on an NFSv4 mount
    point, incorrect file attributes, and outdated file size
    and timestamp information were returned. As well,
    symbolic links may have been displayed as actual files.

  - a bug which caused the cmirror write path to appear
    deadlocked after a successful recovery, which may have
    caused syncing to hang, has been resolved.

  - a kernel panic which occurred when manually configuring
    LCS interfaces on the IBM S/390 has been resolved.

  - when running a 32-bit binary on a 64-bit system, it was
    possible to mmap page at address 0 without flag
    MAP_FIXED set. This has been resolved in these updated
    packages.

  - the Non-Maskable Interrupt (NMI) Watchdog did not
    increment the NMI interrupt counter in
    '/proc/interrupts' on systems running an AMD Opteron
    CPU. This caused systems running NMI Watchdog to restart
    at regular intervals.

  - a bug which caused the diskdump utility to run very
    slowly on devices using Fusion MPT has been resolved."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0712&L=scientific-linux-errata&T=0&P=2872
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?02e1b6e3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/19");
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
if (rpm_check(release:"SL4", reference:"kernel-2.6.9-67.0.1.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-devel-2.6.9-67.0.1.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-doc-2.6.9-67.0.1.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-2.6.9-67.0.1.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-67.0.1.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-67.0.1.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-67.0.1.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-2.6.9-67.0.1.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-devel-2.6.9-67.0.1.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-2.6.9-67.0.1.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-devel-2.6.9-67.0.1.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
