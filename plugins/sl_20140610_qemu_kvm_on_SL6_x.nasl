#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(74490);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/11/06 11:48:15 $");

  script_cve_id("CVE-2013-4148", "CVE-2013-4151", "CVE-2013-4535", "CVE-2013-4536", "CVE-2013-4541", "CVE-2013-4542", "CVE-2013-6399", "CVE-2014-0182", "CVE-2014-2894", "CVE-2014-3461");

  script_name(english:"Scientific Linux Security Update : qemu-kvm on SL6.x i386/x86_64");
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
"Multiple buffer overflow, input validation, and out-of-bounds write
flaws were found in the way the virtio, virtio-net, virtio-scsi, and
usb drivers of QEMU handled state loading after migration. A user able
to alter the savevm data (either on the disk or over the wire during
migration) could use either of these flaws to corrupt QEMU process
memory on the (destination) host, which could potentially result in
arbitrary code execution on the host with the privileges of the QEMU
process. (CVE-2013-4148, CVE-2013-4151, CVE-2013-4535, CVE-2013-4536,
CVE-2013-4541, CVE-2013-4542, CVE-2013-6399, CVE-2014-0182,
CVE-2014-3461)

An out-of-bounds memory access flaw was found in the way QEMU's IDE
device driver handled the execution of SMART EXECUTE OFFLINE commands.
A privileged guest user could use this flaw to corrupt QEMU process
memory on the host, which could potentially result in arbitrary code
execution on the host with the privileges of the QEMU process.
(CVE-2014-2894)

This update also fixes the following bugs :

  - Previously, under certain circumstances, libvirt failed
    to start guests which used a non-zero PCI domain and
    SR-IOV Virtual Functions (VFs), and returned the
    following error message :

Can't assign device inside non-zero PCI segment as this KVM module
doesn't support it.

This update fixes this issue and guests using the aforementioned
configuration no longer fail to start.

  - Due to an incorrect initialization of the cpus_sts
    bitmap, which holds the enablement status of a vCPU,
    libvirt could fail to start a guest with an unusual vCPU
    topology (for example, a guest with three cores and two
    sockets). With this update, the initialization of
    cpus_sts has been corrected, and libvirt no longer fails
    to start the aforementioned guests.

After installing this update, shut down all running virtual machines.
Once all virtual machines have shut down, start them again for this
update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1406&L=scientific-linux-errata&T=0&P=1593
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ea845d1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"qemu-guest-agent-0.12.1.2-2.415.el6_5.10")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-img-0.12.1.2-2.415.el6_5.10")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-kvm-0.12.1.2-2.415.el6_5.10")) flag++;
if (rpm_check(release:"SL6", reference:"qemu-kvm-debuginfo-0.12.1.2-2.415.el6_5.10")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-kvm-tools-0.12.1.2-2.415.el6_5.10")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
