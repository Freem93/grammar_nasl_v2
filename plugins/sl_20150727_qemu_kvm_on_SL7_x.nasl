#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(85072);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/08/13 13:44:24 $");

  script_cve_id("CVE-2015-3214", "CVE-2015-5154");

  script_name(english:"Scientific Linux Security Update : qemu-kvm on SL7.x x86_64");
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
"A heap buffer overflow flaw was found in the way QEMU's IDE subsystem
handled I/O buffer access while processing certain ATAPI commands. A
privileged guest user in a guest with the CDROM drive enabled could
potentially use this flaw to execute arbitrary code on the host with
the privileges of the host's QEMU process corresponding to the guest.
(CVE-2015-5154)

An out-of-bounds memory access flaw, leading to memory corruption or
possibly an information leak, was found in QEMU's pit_ioport_read()
function. A privileged guest user in a QEMU guest, which had QEMU PIT
emulation enabled, could potentially, in rare cases, use this flaw to
execute arbitrary code on the host with the privileges of the hosting
QEMU process. (CVE-2015-3214)

This update also fixes the following bug :

  - Due to an incorrect implementation of portable memory
    barriers, the QEMU emulator in some cases terminated
    unexpectedly when a virtual disk was under heavy I/O
    load. This update fixes the implementation in order to
    achieve correct synchronization between QEMU's threads.
    As a result, the described crash no longer occurs.

After installing this update, shut down all running virtual machines.
Once all virtual machines have shut down, start them again for this
update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1507&L=scientific-linux-errata&F=&S=&P=12261
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e0bc780"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libcacard-1.5.3-86.el7_1.5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libcacard-devel-1.5.3-86.el7_1.5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libcacard-tools-1.5.3-86.el7_1.5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qemu-img-1.5.3-86.el7_1.5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qemu-kvm-1.5.3-86.el7_1.5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qemu-kvm-common-1.5.3-86.el7_1.5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qemu-kvm-debuginfo-1.5.3-86.el7_1.5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qemu-kvm-tools-1.5.3-86.el7_1.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
