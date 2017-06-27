#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(89957);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/03/16 13:32:05 $");

  script_cve_id("CVE-2013-2596", "CVE-2015-2151");

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
"  - An integer overflow flaw was found in the way the Linux
    kernel's Frame Buffer device implementation mapped
    kernel memory to user space via the mmap syscall. A
    local user able to access a frame buffer device file
    (/dev/fb*) could possibly use this flaw to escalate
    their privileges on the system. (CVE-2013-2596,
    Important)

  - It was found that the Xen hypervisor x86 CPU emulator
    implementation did not correctly handle certain
    instructions with segment overrides, potentially
    resulting in a memory corruption. A malicious guest user
    could use this flaw to read arbitrary data relating to
    other guests, cause a denial of service on the host, or
    potentially escalate their privileges on the host.
    (CVE-2015-2151, Important)

This update also fixes the following bugs :

  - Previously, the CPU power of a CPU group could be zero.
    As a consequence, a kernel panic occurred at
    'find_busiest_group+570' with do_divide_error. The
    provided patch ensures that the division is only
    performed if the CPU power is not zero, and the
    aforementioned panic no longer occurs.

  - Prior to this update, a bug occurred when performing an
    online resize of an ext4 file system which had been
    previously converted from ext3. As a consequence, the
    kernel crashed. The provided patch fixes online resizing
    for such file systems by limiting the blockgroup search
    loop for non- extent files, and the mentioned kernel
    crash no longer occurs.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1603&L=scientific-linux-errata&F=&S=&P=5510
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b14baafe"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-409.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-409.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-debuginfo-2.6.18-409.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-409.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-409.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-debuginfo-2.6.18-409.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-409.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-2.6.18-409.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-common-2.6.18-409.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-409.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-409.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-409.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-409.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-debuginfo-2.6.18-409.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-409.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
