#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(64233);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/10/25 23:56:05 $");

  script_cve_id("CVE-2012-0217", "CVE-2012-0218", "CVE-2012-2934");

  script_name(english:"SuSE 11.1 Security Update : Xen (SAT Patch Number 6399)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
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
    to a protection fault bounce. The third fix is changing
    the Xen behaviour on certain hardware:. (CVE-2012-0218)

  - The issue is a denial of service issue on older pre-SVM
    AMD CPUs (AMD Erratum 121). AMD Erratum #121 is
    described in 'Revision Guide for AMD Athlon 64 and AMD
    Opteron Processors':
    http://support.amd.com/us/Processor_TechDocs/25759.pdf.
    (CVE-2012-2934)

    The following 130nm and 90nm (DDR1-only) AMD processors
    are subject to this erratum :

  - First-generation AMD-Opteron(tm) single and dual core
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=757537"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=757970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=764077"
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
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 6399.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"xen-4.0.3_21548_04-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"xen-kmp-default-4.0.3_21548_04_2.6.32.59_0.5-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"xen-kmp-pae-4.0.3_21548_04_2.6.32.59_0.5-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"xen-libs-4.0.3_21548_04-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"xen-tools-4.0.3_21548_04-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"xen-tools-domU-4.0.3_21548_04-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xen-4.0.3_21548_04-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xen-kmp-default-4.0.3_21548_04_2.6.32.59_0.5-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xen-libs-4.0.3_21548_04-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xen-tools-4.0.3_21548_04-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xen-tools-domU-4.0.3_21548_04-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"xen-4.0.3_21548_04-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"xen-doc-html-4.0.3_21548_04-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"xen-doc-pdf-4.0.3_21548_04-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"xen-kmp-default-4.0.3_21548_04_2.6.32.59_0.5-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"xen-kmp-pae-4.0.3_21548_04_2.6.32.59_0.5-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"xen-kmp-trace-4.0.3_21548_04_2.6.32.59_0.5-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"xen-libs-4.0.3_21548_04-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"xen-tools-4.0.3_21548_04-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"xen-tools-domU-4.0.3_21548_04-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-4.0.3_21548_04-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-doc-html-4.0.3_21548_04-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-doc-pdf-4.0.3_21548_04-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-kmp-default-4.0.3_21548_04_2.6.32.59_0.5-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-kmp-trace-4.0.3_21548_04_2.6.32.59_0.5-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-libs-4.0.3_21548_04-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-tools-4.0.3_21548_04-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-tools-domU-4.0.3_21548_04-0.9.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
