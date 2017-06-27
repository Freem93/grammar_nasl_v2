#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:2326-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(87590);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/05/02 15:19:32 $");

  script_cve_id("CVE-2015-5307", "CVE-2015-7311", "CVE-2015-7504", "CVE-2015-7969", "CVE-2015-7970", "CVE-2015-7971", "CVE-2015-7972", "CVE-2015-8104", "CVE-2015-8339", "CVE-2015-8340", "CVE-2015-8341", "CVE-2015-8345");
  script_osvdb_id(128019, 129598, 129599, 129600, 129601, 130089, 130090, 130703, 130888, 131284, 131285, 131453);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : xen (SUSE-SU-2015:2326-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following security issues :

  - bsc#956832 - CVE-2015-8345: xen: qemu: net: eepro100:
    infinite loop in processing command block list

  - bsc#956592 - xen: virtual PMU is unsupported (XSA-163)

  - bsc#956408 - CVE-2015-8339, CVE-2015-8340: xen:
    XENMEM_exchange error handling issues (XSA-159)

  - bsc#956409 - CVE-2015-8341: xen: libxl leak of pv kernel
    and initrd on error (XSA-160)

  - bsc#956411 - CVE-2015-7504: xen: heap buffer overflow
    vulnerability in pcnet emulator (XSA-162)

  - bsc#947165 - CVE-2015-7311: xen: libxl fails to honour
    readonly flag on disks with qemu-xen (xsa-142)

  - bsc#954405 - CVE-2015-8104: Xen: guest to host DoS by
    triggering an infinite loop in microcode via #DB
    exception

  - bsc#954018 - CVE-2015-5307: xen: x86: CPU lockup during
    fault delivery (XSA-156)

  - bsc#950704 - CVE-2015-7970: xen: x86: Long latency
    populate-on-demand operation is not preemptible
    (XSA-150)

  - bsc#951845 - CVE-2015-7972: xen: x86: populate-on-demand
    balloon size inaccuracy can crash guests (XSA-153)

  - bsc#950703 - CVE-2015-7969: xen: leak of main per-domain
    vcpu pointer array (DoS) (XSA-149)

  - bsc#950705 - CVE-2015-7969: xen: x86: leak of per-domain
    profiling-related vcpu pointer array (DoS) (XSA-151)

  - bsc#950706 - CVE-2015-7971: xen: x86: some pmu and
    profiling hypercalls log without rate limiting (XSA-152)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/947165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/950703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/950704"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/950705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/950706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956409"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5307.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7311.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7504.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7969.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7970.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7971.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7972.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8104.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8339.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8340.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8341.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8345.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20152326-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?30e55811"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP3 :

zypper in -t patch sdksp3-xen-20151203-12274=1

SUSE Linux Enterprise Server 11-SP3 :

zypper in -t patch slessp3-xen-20151203-12274=1

SUSE Linux Enterprise Desktop 11-SP3 :

zypper in -t patch sledsp3-xen-20151203-12274=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-xen-20151203-12274=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(SLED11|SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11 / SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! ereg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-kmp-default-4.2.5_18_3.0.101_0.47.71-21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-libs-4.2.5_18-21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-tools-domU-4.2.5_18-21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-4.2.5_18-21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-doc-html-4.2.5_18-21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-doc-pdf-4.2.5_18-21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-libs-32bit-4.2.5_18-21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-tools-4.2.5_18-21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-kmp-pae-4.2.5_18_3.0.101_0.47.71-21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-kmp-default-4.2.5_18_3.0.101_0.47.71-21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-libs-4.2.5_18-21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-tools-domU-4.2.5_18-21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-kmp-pae-4.2.5_18_3.0.101_0.47.71-21.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-kmp-default-4.2.5_18_3.0.101_0.47.71-21.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-libs-4.2.5_18-21.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-tools-domU-4.2.5_18-21.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-4.2.5_18-21.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-doc-html-4.2.5_18-21.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-doc-pdf-4.2.5_18-21.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-libs-32bit-4.2.5_18-21.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-tools-4.2.5_18-21.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-kmp-pae-4.2.5_18_3.0.101_0.47.71-21.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"xen-kmp-default-4.2.5_18_3.0.101_0.47.71-21.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"xen-libs-4.2.5_18-21.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"xen-tools-domU-4.2.5_18-21.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"xen-kmp-pae-4.2.5_18_3.0.101_0.47.71-21.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
