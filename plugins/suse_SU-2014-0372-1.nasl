#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2014:0372-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83613);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_cve_id("CVE-2013-2212", "CVE-2013-4553", "CVE-2013-4554", "CVE-2013-6885", "CVE-2014-1666", "CVE-2014-1891", "CVE-2014-1892", "CVE-2014-1893", "CVE-2014-1894", "CVE-2014-1950");
  script_bugtraq_id(61424, 63931, 63933, 63983, 65125, 65419, 65529);
  script_osvdb_id(95629, 100386, 100387, 100445, 102536, 103006, 103007, 103008, 103009, 103253);

  script_name(english:"SUSE SLES11 Security Update : Xen (SUSE-SU-2014:0372-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise Server 11 Service Pack 2 LTSS Xen hypervisor
and toolset has been updated to fix various security issues and
several bugs.

The following security issues have been addressed :

XSA-88: CVE-2014-1950: Use-after-free vulnerability in the
xc_cpupool_getinfo function in Xen 4.1.x through 4.3.x, when using a
multithreaded toolstack, does not properly handle a failure by the
xc_cpumap_alloc function, which allows local users with access to
management functions to cause a denial of service (heap corruption)
and possibly gain privileges via unspecified vectors. (bnc#861256)

XSA-87: CVE-2014-1666: The do_physdev_op function in Xen
4.1.5, 4.1.6.1, 4.2.2 through 4.2.3, and 4.3.x does not
properly restrict access to the (1) PHYSDEVOP_prepare_msix
and (2) PHYSDEVOP_release_msix operations, which allows
local PV guests to cause a denial of service (host or guest
malfunction) or possibly gain privileges via unspecified
vectors. (bnc#860302)

XSA-84: CVE-2014-1894: Xen 3.2 (and presumably earlier)
exhibit both problems with the overflow issue being present
for more than just the suboperations listed above.
(bnc#860163)

XSA-84: CVE-2014-1892 CVE-2014-1893: Xen 3.3 through 4.1,
while not affected by the above overflow, have a different
overflow issue on FLASK_{GET,SET}BOOL and expose
unreasonably large memory allocation to arbitrary guests.
(bnc#860163)

XSA-84: CVE-2014-1891: The FLASK_{GET,SET}BOOL, FLASK_USER
and FLASK_CONTEXT_TO_SID suboperations of the flask
hypercall are vulnerable to an integer overflow on the input
size. The hypercalls attempt to allocate a buffer which is 1
larger than this size and is therefore vulnerable to integer
overflow and an attempt to allocate then access a zero byte
buffer. (bnc#860163)

XSA-82: CVE-2013-6885: The microcode on AMD 16h 00h through
0Fh processors does not properly handle the interaction
between locked instructions and write-combined memory types,
which allows local users to cause a denial of service
(system hang) via a crafted application, aka the errata 793
issue. (bnc#853049)

XSA-76: CVE-2013-4554: Xen 3.0.3 through 4.1.x (possibly
4.1.6.1), 4.2.x (possibly 4.2.3), and 4.3.x (possibly 4.3.1)
does not properly prevent access to hypercalls, which allows
local guest users to gain privileges via a crafted
application running in ring 1 or 2. (bnc#849668)

XSA-74: CVE-2013-4553: The XEN_DOMCTL_getmemlist hypercall
in Xen 3.4.x through 4.3.x (possibly 4.3.1) does not always
obtain the page_alloc_lock and mm_rwlock in the same order,
which allows local guest administrators to cause a denial of
service (host deadlock). (bnc#849667)

XSA-60: CVE-2013-2212: The vmx_set_uc_mode function in Xen
3.3 through 4.3, when disabling chaches, allows local HVM
guests with access to memory mapped I/O regions to cause a
denial of service (CPU consumption and possibly hypervisor
or guest kernel panic) via a crafted GFN range. (bnc#831120)

Also the following non-security bugs have been fixed :

  - Boot Failure with xen kernel in UEFI mode with error 'No
    memory for trampoline' (bnc#833483)

  - Fixed Xen hypervisor panic on 8-blades nPar with 46-bit
    memory addressing. (bnc#848014)

  - In HP's UEFI x86_64 platform and sles11sp3 with xen
    environment, dom0 will soft lockup on multiple blades
    nPar. (bnc#842417)

  - Soft lockup with PCI passthrough and many VCPUs
    (bnc#846849)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=39ca3113e56362a1b6ff0a74f08124b2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dfc5cc4b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2212.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4553.html"
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
    value:"http://support.novell.com/security/cve/CVE-2014-1950.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/831120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/833483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/842417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/846849"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/848014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/849667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/849668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/853049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/860163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/860302"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/861256"
  );
  # https://www.suse.com/support/update/announcement/2014/suse-su-20140372-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0a9a98b5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11 SP2 LTSS :

zypper in -t patch slessp2-xen-201402-8964

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/13");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^2$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-devel-4.1.6_06-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-kmp-default-4.1.6_06_3.0.101_0.7.17-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-kmp-trace-4.1.6_06_3.0.101_0.7.17-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-libs-4.1.6_06-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-tools-domU-4.1.6_06-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-4.1.6_06-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-doc-html-4.1.6_06-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-doc-pdf-4.1.6_06-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-libs-32bit-4.1.6_06-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-tools-4.1.6_06-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-kmp-pae-4.1.6_06_3.0.101_0.7.17-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-devel-4.1.6_06-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-kmp-default-4.1.6_06_3.0.101_0.7.17-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-kmp-trace-4.1.6_06_3.0.101_0.7.17-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-libs-4.1.6_06-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-tools-domU-4.1.6_06-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-kmp-pae-4.1.6_06_3.0.101_0.7.17-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Xen");
}
