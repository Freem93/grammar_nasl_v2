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
  script_id(73015);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/03/14 13:12:25 $");

  script_cve_id("CVE-2013-2212", "CVE-2013-6400", "CVE-2013-6885", "CVE-2014-1642", "CVE-2014-1666", "CVE-2014-1891", "CVE-2014-1892", "CVE-2014-1893", "CVE-2014-1894", "CVE-2014-1895", "CVE-2014-1896", "CVE-2014-1950");

  script_name(english:"SuSE 11.3 Security Update : Xen (SAT Patch Number 8973)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise Server 11 Service Pack 3 Xen hypervisor and
toolset has been updated to 4.2.4 to fix various bugs and security
issues :

The following security issues have been addressed :

  - XSA-60: CVE-2013-2212: The vmx_set_uc_mode function in
    Xen 3.3 through 4.3, when disabling chaches, allows
    local HVM guests with access to memory mapped I/O
    regions to cause a denial of service (CPU consumption
    and possibly hypervisor or guest kernel panic) via a
    crafted GFN range. (bnc#831120)

  - XSA-80: CVE-2013-6400: Xen 4.2.x and 4.3.x, when using
    Intel VT-d and a PCI device has been assigned, does not
    clear the flag that suppresses IOMMU TLB flushes when
    unspecified errors occur, which causes the TLB entries
    to not be flushed and allows local guest administrators
    to cause a denial of service (host crash) or gain
    privileges via unspecified vectors. (bnc#853048)

  - XSA-82: CVE-2013-6885: The microcode on AMD 16h 00h
    through 0Fh processors does not properly handle the
    interaction between locked instructions and
    write-combined memory types, which allows local users to
    cause a denial of service (system hang) via a crafted
    application, aka the errata 793 issue. (bnc#853049)

  - XSA-83: CVE-2014-1642: The IRQ setup in Xen 4.2.x and
    4.3.x, when using device passthrough and configured to
    support a large number of CPUs, frees certain memory
    that may still be intended for use, which allows local
    guest administrators to cause a denial of service
    (memory corruption and hypervisor crash) and possibly
    execute arbitrary code via vectors related to an
    out-of-memory error that triggers a (1) use-after-free
    or (2) double free. (bnc#860092)

  - XSA-84: CVE-2014-1891: The FLASK_{GET,SET}BOOL,
    FLASK_USER and FLASK_CONTEXT_TO_SID suboperations of the
    flask hypercall are vulnerable to an integer overflow on
    the input size. The hypercalls attempt to allocate a
    buffer which is 1 larger than this size and is therefore
    vulnerable to integer overflow and an attempt to
    allocate then access a zero byte buffer. (bnc#860163)

  - XSA-84: CVE-2014-1892 / CVE-2014-1893: Xen 3.3 through
    4.1, while not affected by the above overflow, have a
    different overflow issue on FLASK_{GET,SET}BOOL and
    expose unreasonably large memory allocation to
    aribitrary guests. (bnc#860163)

  - XSA-84: CVE-2014-1894: Xen 3.2 (and presumably earlier)
    exhibit both problems with the overflow issue being
    present for more than just the suboperations listed
    above. (bnc#860163)

  - XSA-85: CVE-2014-1895: The FLASK_AVC_CACHESTAT
    hypercall, which provides access to per-cpu statistics
    on the Flask security policy, incorrectly validates the
    CPU for which statistics are being requested.
    (bnc#860165)

  - XSA-86: CVE-2014-1896: libvchan (a library for
    inter-domain communication) does not correctly handle
    unusual or malicious contents in the xenstore ring. A
    malicious guest can exploit this to cause a
    libvchan-using facility to read or write past the end of
    the ring. (bnc#860300)

  - XSA-87: CVE-2014-1666: The do_physdev_op function in Xen
    4.1.5, 4.1.6.1, 4.2.2 through 4.2.3, and 4.3.x does not
    properly restrict access to the (1)
    PHYSDEVOP_prepare_msix and (2) PHYSDEVOP_release_msix
    operations, which allows local PV guests to cause a
    denial of service (host or guest malfunction) or
    possibly gain privileges via unspecified vectors.
    (bnc#860302)

  - XSA-88: CVE-2014-1950: Use-after-free vulnerability in
    the xc_cpupool_getinfo function in Xen 4.1.x through
    4.3.x, when using a multithreaded toolstack, does not
    properly handle a failure by the xc_cpumap_alloc
    function, which allows local users with access to
    management functions to cause a denial of service (heap
    corruption) and possibly gain privileges via unspecified
    vectors. (bnc#861256)

Also the following non-security bugs have been fixed :

  - Fixed boot problems with Xen kernel. '(XEN) setup
    0000:00:18.0 for d0 failed (-19)'. (bnc#858311)

  - Fixed Xen hypervisor panic on 8-blades nPar with 46-bit
    memory addressing. (bnc#848014)

  - Fixed Xen hypervisor panic in HP's UEFI x86_64 platform
    and with xen environment, in booting stage. (bnc#833251)

  - xend/pvscsi: recognize also SCSI CDROM devices.
    (bnc#863297)

  - pygrub: Support (/dev/xvda) style disk specifications"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=848014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=853048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=853049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=858311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=860092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=860163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=860165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=860300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=860302"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=861256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=863297"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2212.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6400.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6885.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1642.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1666.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1891.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1892.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1893.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1894.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1895.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1896.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1950.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 8973.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"xen-kmp-default-4.2.4_02_3.0.101_0.15-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"xen-kmp-pae-4.2.4_02_3.0.101_0.15-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"xen-libs-4.2.4_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"xen-tools-domU-4.2.4_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xen-4.2.4_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xen-doc-html-4.2.4_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xen-doc-pdf-4.2.4_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xen-kmp-default-4.2.4_02_3.0.101_0.15-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xen-libs-4.2.4_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xen-libs-32bit-4.2.4_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xen-tools-4.2.4_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xen-tools-domU-4.2.4_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"xen-kmp-default-4.2.4_02_3.0.101_0.15-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"xen-kmp-pae-4.2.4_02_3.0.101_0.15-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"xen-libs-4.2.4_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"xen-tools-domU-4.2.4_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"xen-4.2.4_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"xen-doc-html-4.2.4_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"xen-doc-pdf-4.2.4_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"xen-kmp-default-4.2.4_02_3.0.101_0.15-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"xen-libs-4.2.4_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"xen-libs-32bit-4.2.4_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"xen-tools-4.2.4_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"xen-tools-domU-4.2.4_02-0.7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
