#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(73664);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/04/23 12:45:52 $");

  script_cve_id("CVE-2014-0142", "CVE-2014-0143", "CVE-2014-0144", "CVE-2014-0145", "CVE-2014-0146", "CVE-2014-0147", "CVE-2014-0148", "CVE-2014-0150");

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
"Multiple integer overflow, input validation, logic error, and buffer
overflow flaws were discovered in various QEMU block drivers. An
attacker able to modify a disk image file loaded by a guest could use
these flaws to crash the guest, or corrupt QEMU process memory on the
host, potentially resulting in arbitrary code execution on the host
with the privileges of the QEMU process. (CVE-2014-0143,
CVE-2014-0144, CVE-2014-0145, CVE-2014-0147)

A buffer overflow flaw was found in the way the
virtio_net_handle_mac() function of QEMU processed guest requests to
update the table of MAC addresses. A privileged guest user could use
this flaw to corrupt QEMU process memory on the host, potentially
resulting in arbitrary code execution on the host with the privileges
of the QEMU process. (CVE-2014-0150)

A divide-by-zero flaw was found in the seek_to_sector() function of
the parallels block driver in QEMU. An attacker able to modify a disk
image file loaded by a guest could use this flaw to crash the guest.
(CVE-2014-0142)

A NULL pointer dereference flaw was found in the QCOW2 block driver in
QEMU. An attacker able to modify a disk image file loaded by a guest
could use this flaw to crash the guest. (CVE-2014-0146)

It was found that the block driver for Hyper-V VHDX images did not
correctly calculate BAT (Block Allocation Table) entries due to a
missing bounds check. An attacker able to modify a disk image file
loaded by a guest could use this flaw to crash the guest.
(CVE-2014-0148)

After installing this update, shut down all running virtual machines.
Once all virtual machines have shut down, start them again for this
update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1404&L=scientific-linux-errata&T=0&P=2095
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?03a8fec6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/23");
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
if (rpm_check(release:"SL6", reference:"qemu-guest-agent-0.12.1.2-2.415.el6_5.8")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-img-0.12.1.2-2.415.el6_5.8")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-kvm-0.12.1.2-2.415.el6_5.8")) flag++;
if (rpm_check(release:"SL6", reference:"qemu-kvm-debuginfo-0.12.1.2-2.415.el6_5.8")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-kvm-tools-0.12.1.2-2.415.el6_5.8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
