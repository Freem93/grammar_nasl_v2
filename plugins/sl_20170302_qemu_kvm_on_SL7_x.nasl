#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(97517);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/06 15:01:21 $");

  script_cve_id("CVE-2017-2615", "CVE-2017-2620");
  script_xref(name:"IAVB", value:"2017-B-0024");

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
"Security Fix(es) :

  - Quick emulator (QEMU) built with the Cirrus CLGD 54xx
    VGA emulator support is vulnerable to an out-of-bounds
    access issue. It could occur while copying VGA data via
    bitblt copy in backward mode. A privileged user inside a
    guest could use this flaw to crash the QEMU process
    resulting in DoS or potentially execute arbitrary code
    on the host with privileges of QEMU process on the host.
    (CVE-2017-2615)

  - Quick emulator (QEMU) built with the Cirrus CLGD 54xx
    VGA Emulator support is vulnerable to an out-of-bounds
    access issue. The issue could occur while copying VGA
    data in cirrus_bitblt_cputovideo. A privileged user
    inside guest could use this flaw to crash the QEMU
    process OR potentially execute arbitrary code on host
    with privileges of the QEMU process. (CVE-2017-2620)

Bug Fix(es) :

  - When using the virtio-blk driver on a guest virtual
    machine with no space on the virtual hard drive, the
    guest terminated unexpectedly with a 'block I/O error in
    device' message and the qemu-kvm process exited with a
    segmentation fault. This update fixes how the
    system_reset QEMU signal is handled in the above
    scenario. As a result, if a guest crashes due to no
    space left on the device, qemu-kvm continues running and
    the guest can be reset as expected."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1703&L=scientific-linux-errata&F=&S=&P=406
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a9c693c2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/03");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qemu-img-1.5.3-126.el7_3.5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qemu-kvm-1.5.3-126.el7_3.5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qemu-kvm-common-1.5.3-126.el7_3.5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qemu-kvm-debuginfo-1.5.3-126.el7_3.5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qemu-kvm-tools-1.5.3-126.el7_3.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
