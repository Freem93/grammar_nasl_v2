#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0658-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(89723);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/27 20:14:34 $");

  script_cve_id("CVE-2014-0222", "CVE-2015-4037", "CVE-2015-5239", "CVE-2015-5307", "CVE-2015-7504", "CVE-2015-7512", "CVE-2015-7971", "CVE-2015-8104", "CVE-2015-8339", "CVE-2015-8340", "CVE-2015-8504", "CVE-2015-8550", "CVE-2015-8555");
  script_bugtraq_id(67357, 74809);
  script_osvdb_id(106983, 122500, 127119, 129600, 130089, 130090, 130888, 130889, 131284, 131285, 131399, 132029, 132050);

  script_name(english:"SUSE SLES10 Security Update : Xen (SUSE-SU-2016:0658-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Xen was updated to fix the following vulnerabilities :

CVE-2014-0222: Qcow1 L2 table size integer overflows (bsc#877642)

CVE-2015-4037: Insecure temporary file use in /net/slirp.c
(bsc#932267)

CVE-2015-5239: Integer overflow in vnc_client_read() and
protocol_client_msg() (bsc#944463)

CVE-2015-7504: Heap buffer overflow vulnerability in pcnet emulator
(XSA-162, bsc#956411)

CVE-2015-7971: Some pmu and profiling hypercalls log without rate
limiting (XSA-152, bsc#950706)

CVE-2015-8104: Guest to host DoS by triggering an infinite loop in
microcode via #DB exception (bsc#954405)

CVE-2015-5307: Guest to host DOS by intercepting #AC (XSA-156,
bsc#953527)

CVE-2015-8339: XENMEM_exchange error handling issues (XSA-159,
bsc#956408)

CVE-2015-8340: XENMEM_exchange error handling issues (XSA-159,
bsc#956408)

CVE-2015-7512: Buffer overflow in pcnet's non-loopback mode
(bsc#962360)

CVE-2015-8550: Paravirtualized drivers incautious about shared memory
contents (XSA-155, bsc#957988)

CVE-2015-8504: Avoid floating point exception in vnc support
(bsc#958493)

CVE-2015-8555: Information leak in legacy x86 FPU/XMM initialization
(XSA-165, bsc#958009)

Ioreq handling possibly susceptible to multiple read issue (XSA-166,
bsc#958523)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/877642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/932267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/944463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/950706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/953527"
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
    value:"https://bugzilla.suse.com/956411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962360"
  );
  # https://download.suse.com/patch/finder/?keywords=085198b0d3665c1af17df9c5dcb0be80
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2274b2c7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-0222.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4037.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5239.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5307.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7504.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7512.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7971.html"
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
    value:"https://www.suse.com/security/cve/CVE-2015-8504.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8550.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8555.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160658-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1c1447d6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected Xen packages");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (os_ver == "SLES10" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-3.2.3_17040_46-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-devel-3.2.3_17040_46-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-doc-html-3.2.3_17040_46-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-doc-pdf-3.2.3_17040_46-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-doc-ps-3.2.3_17040_46-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-debug-3.2.3_17040_46_2.6.16.60_0.132.6-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-default-3.2.3_17040_46_2.6.16.60_0.132.6-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-kdump-3.2.3_17040_46_2.6.16.60_0.132.6-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-smp-3.2.3_17040_46_2.6.16.60_0.132.6-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-libs-3.2.3_17040_46-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-tools-3.2.3_17040_46-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-tools-domU-3.2.3_17040_46-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-tools-ioemu-3.2.3_17040_46-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-libs-32bit-3.2.3_17040_46-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-bigsmp-3.2.3_17040_46_2.6.16.60_0.132.6-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-kdumppae-3.2.3_17040_46_2.6.16.60_0.132.6-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-vmi-3.2.3_17040_46_2.6.16.60_0.132.6-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-vmipae-3.2.3_17040_46_2.6.16.60_0.132.6-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-3.2.3_17040_46-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-devel-3.2.3_17040_46-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-doc-html-3.2.3_17040_46-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-doc-pdf-3.2.3_17040_46-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-doc-ps-3.2.3_17040_46-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-debug-3.2.3_17040_46_2.6.16.60_0.132.6-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-default-3.2.3_17040_46_2.6.16.60_0.132.6-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-kdump-3.2.3_17040_46_2.6.16.60_0.132.6-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-smp-3.2.3_17040_46_2.6.16.60_0.132.6-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-libs-3.2.3_17040_46-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-tools-3.2.3_17040_46-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-tools-domU-3.2.3_17040_46-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-tools-ioemu-3.2.3_17040_46-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-bigsmp-3.2.3_17040_46_2.6.16.60_0.132.6-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-kdumppae-3.2.3_17040_46_2.6.16.60_0.132.6-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-vmi-3.2.3_17040_46_2.6.16.60_0.132.6-0.23.2")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-vmipae-3.2.3_17040_46_2.6.16.60_0.132.6-0.23.2")) flag++;


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
