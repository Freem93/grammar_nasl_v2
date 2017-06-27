#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0613-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83707);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/05/11 13:40:21 $");

  script_cve_id("CVE-2014-3615", "CVE-2014-9065", "CVE-2014-9066", "CVE-2015-0361", "CVE-2015-2044", "CVE-2015-2045", "CVE-2015-2151", "CVE-2015-2152");
  script_bugtraq_id(69654, 71544, 71546, 71882, 72954, 72955, 73015, 73068);
  script_osvdb_id(111030, 119166, 119202, 119410, 119565);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : Xen (SUSE-SU-2015:0613-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The XEN hypervisor received updates to fix various security issues and
bugs.

The following security issues were fixed :

  - CVE-2015-2151: XSA-123: A hypervisor memory corruption
    due to x86 emulator flaw.

  - CVE-2015-2045: XSA-122: Information leak through version
    information hypercall.

  - CVE-2015-2044: XSA-121: Information leak via internal
    x86 system device emulation.

  - CVE-2015-2152: XSA-119: HVM qemu was unexpectedly
    enabling emulated VGA graphics backends.

  - CVE-2014-3615: Information leakage when guest sets high
    graphics resolution.

  - CVE-2015-0361: XSA-116: A xen crash due to use after
    free on hvm guest teardown.

  - CVE-2014-9065, CVE-2014-9066: XSA-114: xen: p2m lock
    starvation.

Also the following bugs were fixed :

  - bnc#919098 - XEN blktap device intermittently fails to
    connect

  - bnc#882089 - Windows 2012 R2 fails to boot up with
    greater than 60 vcpus

  - bnc#903680 - Problems with detecting free loop devices
    on Xen guest startup

  - bnc#861318 - xentop reports 'Found interface vif101.0
    but domain 101 does not exist.'

  - Update seabios to rel-1.7.3.1 which is the correct
    version for Xen 4.4

  - Enhancement to virsh/libvirtd 'send-key' command The xen
    side small fix. (FATE#317240)

  - bnc#901488 - Intel ixgbe driver assigns rx/tx queues per
    core resulting in irq problems on servers with a large
    amount of CPU cores

  - bnc#910254 - SLES11 SP3 Xen VT-d igb NIC doesn't work

  - Add domain_migrate_constraints_set API to Xend's http
    interface (FATE#317239)

  - Restore missing fixes from block-dmmd script

  - bnc#904255 - XEN boot hangs in early boot on UEFI system

  - bsc#912011 - high ping latency after upgrade to latest
    SLES11SP3 on xen Dom0

  - Fix missing banner by restoring the figlet program.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3615.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-9065.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-9066.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0361.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-2044.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-2045.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-2151.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-2152.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/861318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/882089"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/895528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/901488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/903680"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/904255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/906996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/910254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/910681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/912011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/918995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/918998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/919098"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/919464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/919663"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150613-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b4eac41b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-147=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-147=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-147=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
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
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-4.4.1_10-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-debugsource-4.4.1_10-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-doc-html-4.4.1_10-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-kmp-default-4.4.1_10_k3.12.36_38-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-kmp-default-debuginfo-4.4.1_10_k3.12.36_38-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-32bit-4.4.1_10-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-4.4.1_10-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.4.1_10-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-debuginfo-4.4.1_10-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-4.4.1_10-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-debuginfo-4.4.1_10-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-domU-4.4.1_10-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-domU-debuginfo-4.4.1_10-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-4.4.1_10-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-debugsource-4.4.1_10-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-kmp-default-4.4.1_10_k3.12.36_38-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-kmp-default-debuginfo-4.4.1_10_k3.12.36_38-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-libs-32bit-4.4.1_10-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-libs-4.4.1_10-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.4.1_10-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-libs-debuginfo-4.4.1_10-9.1")) flag++;


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
