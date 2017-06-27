#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2014:0411-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83614);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_cve_id("CVE-2012-4544", "CVE-2013-1917", "CVE-2013-1920", "CVE-2013-2194", "CVE-2013-2195", "CVE-2013-2196", "CVE-2013-4355", "CVE-2013-4368", "CVE-2013-4494", "CVE-2013-4554", "CVE-2013-6885");
  script_bugtraq_id(56289, 58880, 59291, 60701, 60702, 60703, 62708, 62935, 63494, 63931, 63983);
  script_osvdb_id(86619, 92050, 92564, 94077, 94442, 94443, 97955, 98290, 99257, 100386, 100445);

  script_name(english:"SUSE SLES10 Security Update : Xen (SUSE-SU-2014:0411-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise Server 10 Service Pack 4 LTSS Xen hypervisor
and toolset have been updated to fix various security issues.

The following security issues have been addressed :

  - XSA-82: CVE-2013-6885: The microcode on AMD 16h 00h
    through 0Fh processors does not properly handle the
    interaction between locked instructions and
    write-combined memory types, which allows local users to
    cause a denial of service (system hang) via a crafted
    application, aka the errata 793 issue. (bnc#853049)

  - XSA-76: CVE-2013-4554: Xen 3.0.3 through 4.1.x (possibly
    4.1.6.1), 4.2.x (possibly 4.2.3), and 4.3.x (possibly
    4.3.1) does not properly prevent access to hypercalls,
    which allows local guest users to gain privileges via a
    crafted application running in ring 1 or 2. (bnc#849668)

  - XSA-73: CVE-2013-4494: Xen before 4.1.x, 4.2.x, and
    4.3.x does not take the page_alloc_lock and
    grant_table.lock in the same order, which allows local
    guest administrators with access to multiple vcpus to
    cause a denial of service (host deadlock) via
    unspecified vectors. (bnc#848657)

  - XSA-67: CVE-2013-4368: The outs instruction emulation in
    Xen 3.1.x, 4.2.x, 4.3.x, and earlier, when using FS: or
    GS: segment override, uses an uninitialized variable as
    a segment base, which allows local 64-bit PV guests to
    obtain sensitive information (hypervisor stack content)
    via unspecified vectors related to stale data in a
    segment register. (bnc#842511)

  - XSA-63: CVE-2013-4355: Xen 4.3.x and earlier does not
    properly handle certain errors, which allows local HVM
    guests to obtain hypervisor stack memory via a (1) port
    or (2) memory mapped I/O write or (3) other unspecified
    operations related to addresses without associated
    memory. (bnc#840592)

  - XSA-55: CVE-2013-2196: Multiple unspecified
    vulnerabilities in the Elf parser (libelf) in Xen 4.2.x
    and earlier allow local guest administrators with
    certain permissions to have an unspecified impact via a
    crafted kernel, related to 'other problems' that are not
    CVE-2013-2194 or CVE-2013-2195. (bnc#823011)

  - XSA-55: CVE-2013-2195: The Elf parser (libelf) in Xen
    4.2.x and earlier allow local guest administrators with
    certain permissions to have an unspecified impact via a
    crafted kernel, related to 'pointer dereferences'
    involving unexpected calculations. (bnc#823011)

  - XSA-55: CVE-2013-2194: Multiple integer overflows in the
    Elf parser (libelf) in Xen 4.2.x and earlier allow local
    guest administrators with certain permissions to have an
    unspecified impact via a crafted kernel. (bnc#823011)

  - XSA-47: CVE-2013-1920: Xen 4.2.x, 4.1.x, and earlier,
    when the hypervisor is running 'under memory pressure'
    and the Xen Security Module (XSM) is enabled, uses the
    wrong ordering of operations when extending the
    per-domain event channel tracking table, which causes a
    use-after-free and allows local guest kernels to inject
    arbitrary events and gain privileges via unspecified
    vectors. (bnc#813677)

  - XSA-44: CVE-2013-1917: Xen 3.1 through 4.x, when running
    64-bit hosts on Intel CPUs, does not clear the NT flag
    when using an IRET after a SYSENTER instruction, which
    allows PV guest users to cause a denial of service
    (hypervisor crash) by triggering a #GP fault, which is
    not properly handled by another IRET instruction.
    (bnc#813673)

  - XSA-25: CVE-2012-4544: The PV domain builder in Xen 4.2
    and earlier does not validate the size of the kernel or
    ramdisk (1) before or (2) after decompression, which
    allows local guest administrators to cause a denial of
    service (domain 0 memory consumption) via a crafted (a)
    kernel or (b) ramdisk. (bnc#787163)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=5877b583cb5aa03d08203d887cc47ee3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?19638f54"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4544.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1917.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1920.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2194.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2195.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2196.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4355.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4368.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4494.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4554.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6885.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/787163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/813673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/813677"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/823011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/840592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/842511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/848657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/849668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/853049"
  );
  # https://www.suse.com/support/update/announcement/2014/suse-su-20140411-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?132b6f16"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/20");
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
if (! ereg(pattern:"^(SLES10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES10" && (! ereg(pattern:"^4$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-3.2.3_17040_46-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-devel-3.2.3_17040_46-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-doc-html-3.2.3_17040_46-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-doc-pdf-3.2.3_17040_46-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-doc-ps-3.2.3_17040_46-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-debug-3.2.3_17040_46_2.6.16.60_0.103.13-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-default-3.2.3_17040_46_2.6.16.60_0.103.13-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-kdump-3.2.3_17040_46_2.6.16.60_0.103.13-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-smp-3.2.3_17040_46_2.6.16.60_0.103.13-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-libs-3.2.3_17040_46-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-tools-3.2.3_17040_46-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-tools-domU-3.2.3_17040_46-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-tools-ioemu-3.2.3_17040_46-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-libs-32bit-3.2.3_17040_46-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-bigsmp-3.2.3_17040_46_2.6.16.60_0.103.13-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-kdumppae-3.2.3_17040_46_2.6.16.60_0.103.13-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-vmi-3.2.3_17040_46_2.6.16.60_0.103.13-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-vmipae-3.2.3_17040_46_2.6.16.60_0.103.13-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-3.2.3_17040_46-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-devel-3.2.3_17040_46-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-doc-html-3.2.3_17040_46-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-doc-pdf-3.2.3_17040_46-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-doc-ps-3.2.3_17040_46-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-debug-3.2.3_17040_46_2.6.16.60_0.103.13-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-default-3.2.3_17040_46_2.6.16.60_0.103.13-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-kdump-3.2.3_17040_46_2.6.16.60_0.103.13-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-smp-3.2.3_17040_46_2.6.16.60_0.103.13-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-libs-3.2.3_17040_46-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-tools-3.2.3_17040_46-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-tools-domU-3.2.3_17040_46-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-tools-ioemu-3.2.3_17040_46-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-bigsmp-3.2.3_17040_46_2.6.16.60_0.103.13-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-kdumppae-3.2.3_17040_46_2.6.16.60_0.103.13-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-vmi-3.2.3_17040_46_2.6.16.60_0.103.13-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-vmipae-3.2.3_17040_46_2.6.16.60_0.103.13-0.7.1")) flag++;


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
