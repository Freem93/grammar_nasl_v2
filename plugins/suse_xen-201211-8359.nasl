#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62963);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/11/23 15:02:56 $");

  script_cve_id("CVE-2012-4535", "CVE-2012-4537");

  script_name(english:"SuSE 10 Security Update : Xen (ZYPP Patch Number 8359)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"XEN received various security and bugfixes :

  - xen: Timer overflow DoS vulnerability (XSA-20).
    (CVE-2012-4535)

  - xen: Memory mapping failure DoS vulnerability (XSA-22)
    The following additional bugs have beenfixed:.
    (CVE-2012-4537)

  - L3: Xen BUG at io_apic.c:129
    26102-x86-IOAPIC-legacy-not-first.patch. (bnc#784087)

  - Upstream patches from Jan
    25927-x86-domctl-ioport-mapping-range.patch
    25931-x86-domctl-iomem-mapping-checks.patch
    26061-x86-oprof-counter-range.patch
    25431-x86-EDD-MBR-sig-check.patch
    25480-x86_64-sysret-canonical.patch
    25481-x86_64-AMD-erratum-121.patch
    25485-x86_64-canonical-checks.patch
    25587-param-parse-limit.patch
    25589-pygrub-size-limits.patch
    25744-hypercall-return-long.patch
    25765-x86_64-allow-unsafe-adjust.patch
    25773-x86-honor-no-real-mode.patch
    25786-x86-prefer-multiboot-meminfo-over-e801.patch
    25808-domain_create-return-value.patch
    25814-x86_64-set-debugreg-guest.patch
    24742-gnttab-misc.patch 25098-x86-emul-lock-UD.patch
    25200-x86_64-trap-bounce-flags.patch
    25271-x86_64-IST-index.patch

  - win2k8 guests are unable to restore after saving the vms
    state ept-novell-x64.patch
    23800-x86_64-guest-addr-range.patch
    24168-x86-vioapic-clear-remote_irr.patch
    24453-x86-vIRQ-IRR-TMR-race.patch
    24456-x86-emul-lea.patch. (bnc#651093)

  - Unable to install RHEL 6.1 x86 as a paravirtualized
    guest OS on SLES 10 SP4 x86 vm-install-0.2.19.tar.bz2.
    (bnc#713555)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4535.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4537.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8359.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/19");
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
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"xen-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"xen-devel-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"xen-doc-html-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"xen-doc-pdf-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"xen-doc-ps-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"xen-kmp-bigsmp-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"xen-kmp-default-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"xen-kmp-smp-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"xen-libs-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"xen-tools-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"xen-tools-domU-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"xen-tools-ioemu-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"xen-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"xen-devel-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"xen-doc-html-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"xen-doc-pdf-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"xen-doc-ps-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"xen-kmp-default-3.2.3_17040_42_2.6.16.60_0.99.11-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"xen-kmp-smp-3.2.3_17040_42_2.6.16.60_0.99.11-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"xen-libs-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"xen-libs-32bit-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"xen-tools-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"xen-tools-domU-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"xen-tools-ioemu-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-devel-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-doc-html-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-doc-pdf-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-doc-ps-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-kmp-bigsmp-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-kmp-debug-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-kmp-default-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-kmp-kdump-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-kmp-kdumppae-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-kmp-smp-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-kmp-vmi-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-kmp-vmipae-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-libs-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-tools-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-tools-domU-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"xen-tools-ioemu-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"xen-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"xen-devel-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"xen-doc-html-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"xen-doc-pdf-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"xen-doc-ps-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"xen-kmp-debug-3.2.3_17040_42_2.6.16.60_0.99.11-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"xen-kmp-default-3.2.3_17040_42_2.6.16.60_0.99.11-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"xen-kmp-kdump-3.2.3_17040_42_2.6.16.60_0.99.11-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"xen-kmp-smp-3.2.3_17040_42_2.6.16.60_0.99.11-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"xen-libs-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"xen-libs-32bit-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"xen-tools-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"xen-tools-domU-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"xen-tools-ioemu-3.2.3_17040_42-0.7.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else exit(0, "The host is not affected.");
