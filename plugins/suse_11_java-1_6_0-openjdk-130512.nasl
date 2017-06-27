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
  script_id(66538);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/11/18 01:35:30 $");

  script_cve_id("CVE-2013-0401", "CVE-2013-1488", "CVE-2013-1518", "CVE-2013-1537", "CVE-2013-1557", "CVE-2013-1569", "CVE-2013-2383", "CVE-2013-2384", "CVE-2013-2415", "CVE-2013-2417", "CVE-2013-2419", "CVE-2013-2420", "CVE-2013-2421", "CVE-2013-2422", "CVE-2013-2424", "CVE-2013-2426", "CVE-2013-2429", "CVE-2013-2430", "CVE-2013-2431");

  script_name(english:"SuSE 11.2 Security Update : java-1_6_0-openjdk (SAT Patch Number 7718)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"java-1_6_0-openjdk has been updated to version Icedtea6-1.12.5 which
fixes several security issues.

Security fixes

  - S6657673, CVE-2013-1518: Issues with JAXP

  - S7200507: Refactor Introspector internals

  - S8000724, CVE-2013-2417: Improve networking
    serialization

  - S8001031, CVE-2013-2419: Better font processing

  - S8001040, CVE-2013-1537: Rework RMI model

  - S8001322: Refactor deserialization

  - S8001329, CVE-2013-1557: Augment RMI logging

  - S8003335: Better handling of Finalizer thread

  - S8003445: Adjust JAX-WS to focus on API

  - S8003543, CVE-2013-2415: Improve processing of MTOM
    attachments

  - S8004261: Improve input validation

  - S8004336, CVE-2013-2431: Better handling of method
    handle intrinsic frames

  - S8004986, CVE-2013-2383: Better handling of glyph table

  - S8004987, CVE-2013-2384: Improve font layout

  - S8004994, CVE-2013-1569: Improve checking of glyph table

  - S8005432: Update access to JAX-WS

  - S8005943: (process) Improved Runtime.exec

  - S8006309: More reliable control panel operation

  - S8006435, CVE-2013-2424: Improvements in JMX

  - S8006790: Improve checking for windows

  - S8006795: Improve font warning messages

  - S8007406: Improve accessibility of AccessBridge

  - S8007617, CVE-2013-2420: Better validation of images

  - S8007667, CVE-2013-2430: Better image reading

  - S8007918, CVE-2013-2429: Better image writing

  - S8009063, CVE-2013-2426: Improve reliability of
    ConcurrentHashMap

  - S8009305, CVE-2013-0401: Improve AWT data transfer

  - S8009699, CVE-2013-2421: Methodhandle lookup

  - S8009814, CVE-2013-1488: Better driver management

  - S8009857, CVE-2013-2422: Problem with plugin

  - RH952389: Temporary files created with insecure
    permissions Backports

  - S7197906: BlockOffsetArray::power_to_cards_back() needs
    to handle > 32 bit shifts

  - S7036559: ConcurrentHashMap footprint and contention
    improvements

  - S5102804: Memory leak in Introspector.getBeanInfo(Class)
    for custom BeanInfo: Class param (with WeakCache from
    S6397609)

  - S6501644: sync LayoutEngine code structure to match ICU

  - S6886358: layout code update

  - S6963811: Deadlock-prone locking changes in Introspector

  - S7017324: Kerning crash in JDK 7 since ICU layout update

  - S7064279: Introspector.getBeanInfo() should release some
    resources in timely manner

  - S8004302: javax/xml/soap/Test7013971.java fails since
    jdk6u39b01

  - S7133220: Additional patches to JAXP 1.4.5 update 1 for
    7u4 (partial for S6657673)

  - S8009530: ICU Kern table support broken Bug fixes

  - OJ3: Fix get_stack_bounds memory leak (alternate fix for
    S7197906)

  - PR1362: Fedora 19 / rawhide FTBFS SIGILL

  - PR1338: Remove dependence on libXp

  - PR1339: Simplify the rhino class rewriter to avoid use
    of concurrency

  - PR1336: Bootstrap failure on Fedora 17/18

  - PR1319: Correct #ifdef to #if

  - PR1402: Support glibc < 2.17 with AArch64 patch

  - Give xalan/xerces access to their own internal packages.
    New features

  - JAXP, JAXWS &amp; JAF supplied as patches rather than
    drops to aid subsequent patching.

  - PR1380: Add AArch64 support to Zero"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=817157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0401.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1488.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1518.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1537.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1557.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1569.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2383.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2384.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2415.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2417.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2419.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2420.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2421.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2422.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2424.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2426.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2429.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2430.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2431.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 7718.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Driver Manager Privileged toString() Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/22");
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
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"java-1_6_0-openjdk-1.6.0.0_b27.1.12.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"java-1_6_0-openjdk-demo-1.6.0.0_b27.1.12.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"java-1_6_0-openjdk-devel-1.6.0.0_b27.1.12.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"java-1_6_0-openjdk-1.6.0.0_b27.1.12.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"java-1_6_0-openjdk-demo-1.6.0.0_b27.1.12.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"java-1_6_0-openjdk-devel-1.6.0.0_b27.1.12.5-0.2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
