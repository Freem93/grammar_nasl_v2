#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2012:1487-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83564);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_cve_id("CVE-2012-3497", "CVE-2012-4411", "CVE-2012-4535", "CVE-2012-4536", "CVE-2012-4537", "CVE-2012-4538", "CVE-2012-4539", "CVE-2012-4544");
  script_bugtraq_id(55410, 55442, 56289, 56498);

  script_name(english:"SUSE SLED10 / SLES10 Security Update : Xen (SUSE-SU-2012:1487-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"XEN received various security and bugfixes :

  - CVE-2012-4535: xen: Timer overflow DoS vulnerability
    (XSA-20)

  - CVE-2012-4537: xen: Memory mapping failure DoS
    vulnerability (XSA-22)

The following additional bugs have been fixed :

  - bnc#784087 - L3: Xen BUG at io_apic.c:129
    26102-x86-IOAPIC-legacy-not-first.patch

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
    25271-x86_64-IST-index.patch bnc#651093 - win2k8 guests
    are unable to restore after saving the vms state
    ept-novell-x64.patch 23800-x86_64-guest-addr-range.patch
    24168-x86-vioapic-clear-remote_irr.patch
    24453-x86-vIRQ-IRR-TMR-race.patch
    24456-x86-emul-lea.patch

    bnc#713555 - Unable to install RHEL 6.1 x86 as a
    paravirtualized guest OS on SLES 10 SP4 x86
    vm-install-0.2.19.tar.bz2

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=1e9042debead5d88c23444a904a4e0c9
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9eafc586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3497.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4411.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4535.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4536.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4537.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4538.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4539.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4544.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/651093"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/713555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/784087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/786516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/786517"
  );
  # https://www.suse.com/support/update/announcement/2012/suse-su-20121487-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?88058f84"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected Xen packages");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-ps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-kdumppae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-vmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-vmipae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-ioemu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED10|SLES10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED10 / SLES10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED10" && (! ereg(pattern:"^4$", string:sp))) audit(AUDIT_OS_NOT, "SLED10 SP4", os_ver + " SP" + sp);
if (os_ver == "SLES10" && (! ereg(pattern:"^4$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"xen-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"xen-devel-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"xen-doc-html-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"xen-doc-pdf-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"xen-doc-ps-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"xen-kmp-default-3.2.3_17040_42_2.6.16.60_0.99.11-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"xen-kmp-smp-3.2.3_17040_42_2.6.16.60_0.99.11-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"xen-libs-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"xen-libs-32bit-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"xen-tools-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"xen-tools-domU-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"xen-tools-ioemu-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"xen-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"xen-devel-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"xen-doc-html-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"xen-doc-pdf-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"xen-doc-ps-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"xen-kmp-bigsmp-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"xen-kmp-default-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"xen-kmp-smp-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"xen-libs-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"xen-tools-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"xen-tools-domU-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"xen-tools-ioemu-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"xen-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"xen-devel-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"xen-doc-html-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"xen-doc-pdf-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"xen-doc-ps-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"xen-kmp-bigsmp-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"xen-kmp-default-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"xen-kmp-smp-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"xen-libs-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"xen-tools-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"xen-tools-domU-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"xen-tools-ioemu-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-devel-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-doc-html-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-doc-pdf-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-doc-ps-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-debug-3.2.3_17040_42_2.6.16.60_0.99.11-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-default-3.2.3_17040_42_2.6.16.60_0.99.11-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-kdump-3.2.3_17040_42_2.6.16.60_0.99.11-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-smp-3.2.3_17040_42_2.6.16.60_0.99.11-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-libs-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-libs-32bit-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-tools-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-tools-domU-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-tools-ioemu-3.2.3_17040_42-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-devel-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-doc-html-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-doc-pdf-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-doc-ps-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-bigsmp-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-debug-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-default-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-kdump-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-kdumppae-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-smp-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-vmi-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-vmipae-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-libs-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-tools-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-tools-domU-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-tools-ioemu-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-devel-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-doc-html-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-doc-pdf-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-doc-ps-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-bigsmp-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-debug-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-default-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-kdump-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-kdumppae-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-smp-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-vmi-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-vmipae-3.2.3_17040_42_2.6.16.60_0.99.8-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-libs-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-tools-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-tools-domU-3.2.3_17040_42-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-tools-ioemu-3.2.3_17040_42-0.7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Xen");
}
