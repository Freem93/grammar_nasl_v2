#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62025);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2012/11/27 11:48:16 $");

  script_cve_id("CVE-2012-2625", "CVE-2012-3494", "CVE-2012-3515");

  script_name(english:"SuSE 10 Security Update : Xen (ZYPP Patch Number 8268)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"XEN was updated to fix multiple bugs and security issues.

The following security issues have been fixed :

  - xen: hypercall set_debugreg vulnerability (XSA-12).
    (CVE-2012-3494)

  - xen: Qemu VT100 emulation vulnerability (XSA-17).
    (CVE-2012-3515)

  - xen: pv bootloader doesn't check the size of the bzip2
    or lzma compressed kernel, leading to denial of service.
    (CVE-2012-2625)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2625.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3494.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3515.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8268.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-3.2.3_17040_40-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-devel-3.2.3_17040_40-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-doc-html-3.2.3_17040_40-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-doc-pdf-3.2.3_17040_40-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-doc-ps-3.2.3_17040_40-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-kmp-default-3.2.3_17040_40_2.6.16.60_0.97.32-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-kmp-smp-3.2.3_17040_40_2.6.16.60_0.97.32-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-libs-3.2.3_17040_40-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-tools-3.2.3_17040_40-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-tools-domU-3.2.3_17040_40-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-tools-ioemu-3.2.3_17040_40-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"xen-kmp-bigsmp-3.2.3_17040_40_2.6.16.60_0.97.32-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"xen-libs-32bit-3.2.3_17040_40-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-3.2.3_17040_40-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-devel-3.2.3_17040_40-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-doc-html-3.2.3_17040_40-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-doc-pdf-3.2.3_17040_40-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-doc-ps-3.2.3_17040_40-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-kmp-debug-3.2.3_17040_40_2.6.16.60_0.97.32-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-kmp-default-3.2.3_17040_40_2.6.16.60_0.97.32-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-kmp-kdump-3.2.3_17040_40_2.6.16.60_0.97.32-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-kmp-smp-3.2.3_17040_40_2.6.16.60_0.97.32-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-libs-3.2.3_17040_40-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-tools-3.2.3_17040_40-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-tools-domU-3.2.3_17040_40-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-tools-ioemu-3.2.3_17040_40-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-kmp-bigsmp-3.2.3_17040_40_2.6.16.60_0.97.32-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-kmp-kdumppae-3.2.3_17040_40_2.6.16.60_0.97.32-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-kmp-vmi-3.2.3_17040_40_2.6.16.60_0.97.32-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-kmp-vmipae-3.2.3_17040_40_2.6.16.60_0.97.32-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"xen-libs-32bit-3.2.3_17040_40-0.7.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
