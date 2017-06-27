#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(65076);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/03/07 11:52:04 $");

  script_cve_id("CVE-2012-3400");

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

  - Buffer overflow flaws were found in the
    udf_load_logicalvol() function in the Universal Disk
    Format (UDF) file system implementation in the Linux
    kernel. An attacker with physical access to a system
    could use these flaws to cause a denial of service or
    escalate their privileges. (CVE-2012-3400, Low)

This update also fixes the following bugs :

  - Previously, race conditions could sometimes occur in
    interrupt handling on the Emulex BladeEngine 2 (BE2)
    controllers, causing the network adapter to become
    unresponsive. This update provides a series of patches
    for the be2net driver, which prevents the race from
    occurring. The network cards using BE2 chipsets no
    longer hang due to incorrectly handled interrupt events.

  - A boot-time memory allocation pool (the DMI heap) is
    used to keep the list of Desktop Management Interface
    (DMI) devices during the system boot. Previously, the
    size of the DMI heap was only 2048 bytes on the AMD64
    and Intel 64 architectures and the DMI heap space could
    become easily depleted on some systems, such as the IBM
    System x3500 M2. A subsequent OOM failure could, under
    certain circumstances, lead to a NULL pointer entry
    being stored in the DMI device list. Consequently,
    scanning of such a corrupted DMI device list resulted in
    a kernel panic. The boot-time memory allocation pool for
    the AMD64 and Intel 64 architectures has been enlarged
    to 4096 bytes and the routines responsible for
    populating the DMI device list have been modified to
    skip entries if their name string is NULL. The kernel no
    longer panics in this scenario.

  - The size of the buffer used to print the kernel taint
    output on kernel panic was too small, which resulted in
    the kernel taint output not being printed completely
    sometimes. With this update, the size of the buffer has
    been adjusted and the kernel taint output is now
    displayed properly.

  - The code to print the kernel taint output contained a
    typographical error. Consequently, the kernel taint
    output, which is displayed on kernel panic, could not
    provide taint error messages for unsupported hardware.
    This update fixes the typo and the kernel taint output
    is now displayed correctly.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1303&L=scientific-linux-errata&T=0&P=2051
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e3bcba26"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-348.2.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-348.2.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-debuginfo-2.6.18-348.2.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-348.2.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-348.2.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-debuginfo-2.6.18-348.2.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-348.2.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-2.6.18-348.2.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-common-2.6.18-348.2.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-348.2.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-348.2.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-348.2.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-348.2.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-debuginfo-2.6.18-348.2.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-348.2.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
