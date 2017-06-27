#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59469);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2012/11/16 11:51:00 $");

  script_cve_id("CVE-2012-0217", "CVE-2012-0218", "CVE-2012-2934");

  script_name(english:"SuSE 10 Security Update : Xen (ZYPP Patch Number 8180)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Three security issues were found in XEN.

Two security issues are fixed by this update :

  - Due to incorrect fault handling in the XEN hypervisor it
    was possible for a XEN guest domain administrator to
    execute code in the XEN host environment.
    (CVE-2012-0217)

  - Also a guest user could crash the guest XEN kernel due
    to a protection fault bounce. (CVE-2012-0218)

The third fix is changing the Xen behaviour on certain hardware :

  - The issue is a denial of service issue on older pre-SVM
    AMD CPUs (AMD Erratum 121). (CVE-2012-2934)

    AMD Erratum #121 is described in 'Revision Guide for AMD
    Athlon 64 and AMD Opteron Processors':
    http://support.amd.com/us/Processor_TechDocs/25759.pdf

    The following 130nm and 90nm (DDR1-only) AMD processors
    are subject to this erratum :

o

First-generation AMD-Opteron(tm) single and dual core
processors in either 939 or 940 packages :

  - AMD Opteron(tm) 100-Series Processors

  - AMD Opteron(tm) 200-Series Processors

  - AMD Opteron(tm) 800-Series Processors

  - AMD Athlon(tm) processors in either 754, 939 or 940
    packages

  - AMD Sempron(tm) processor in either 754 or 939 packages

  - AMD Turion(tm) Mobile Technology in 754 package This
    issue does not effect Intel processors.

    The impact of this flaw is that a malicious PV guest
    user can halt the host system.

    As this is a hardware flaw, it is not fixable except by
    upgrading your hardware to a newer revision, or not
    allowing untrusted 64bit guestsystems.

    The patch changes the behaviour of the host system
    booting, which makes it unable to create guest machines
    until a specific boot option is set.

    There is a new XEN boot option 'allow_unsafe' for GRUB
    which allows the host to start guests again.

    This is added to /boot/grub/menu.lst in the line looking
    like this :

    kernel /boot/xen.gz .... allow_unsafe

    Note: .... in this example represents the existing boot
    options for the host."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0217.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0218.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2934.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8180.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/13");
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
if (rpm_check(release:"SLED10", sp:4, reference:"xen-3.2.3_17040_38-0.11.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-devel-3.2.3_17040_38-0.11.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-doc-html-3.2.3_17040_38-0.11.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-doc-pdf-3.2.3_17040_38-0.11.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-doc-ps-3.2.3_17040_38-0.11.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-kmp-default-3.2.3_17040_38_2.6.16.60_0.97.1-0.11.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-kmp-smp-3.2.3_17040_38_2.6.16.60_0.97.1-0.11.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-libs-3.2.3_17040_38-0.11.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-tools-3.2.3_17040_38-0.11.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-tools-domU-3.2.3_17040_38-0.11.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xen-tools-ioemu-3.2.3_17040_38-0.11.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"xen-kmp-bigsmp-3.2.3_17040_38_2.6.16.60_0.97.1-0.11.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"xen-libs-32bit-3.2.3_17040_38-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-3.2.3_17040_38-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-devel-3.2.3_17040_38-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-doc-html-3.2.3_17040_38-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-doc-pdf-3.2.3_17040_38-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-doc-ps-3.2.3_17040_38-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-kmp-debug-3.2.3_17040_38_2.6.16.60_0.97.1-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-kmp-default-3.2.3_17040_38_2.6.16.60_0.97.1-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-kmp-kdump-3.2.3_17040_38_2.6.16.60_0.97.1-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-kmp-smp-3.2.3_17040_38_2.6.16.60_0.97.1-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-libs-3.2.3_17040_38-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-tools-3.2.3_17040_38-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-tools-domU-3.2.3_17040_38-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xen-tools-ioemu-3.2.3_17040_38-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-kmp-bigsmp-3.2.3_17040_38_2.6.16.60_0.97.1-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-kmp-kdumppae-3.2.3_17040_38_2.6.16.60_0.97.1-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-kmp-vmi-3.2.3_17040_38_2.6.16.60_0.97.1-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-kmp-vmipae-3.2.3_17040_38_2.6.16.60_0.97.1-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"xen-libs-32bit-3.2.3_17040_38-0.11.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
