#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:084. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(46176);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/11/28 21:39:24 $");

  script_cve_id(
    "CVE-2009-2409",
    "CVE-2009-3555",
    "CVE-2009-3728",
    "CVE-2009-3869",
    "CVE-2009-3871",
    "CVE-2009-3873",
    "CVE-2009-3874",
    "CVE-2009-3875",
    "CVE-2009-3876",
    "CVE-2009-3877",
    "CVE-2009-3879",
    "CVE-2009-3880",
    "CVE-2009-3881",
    "CVE-2009-3882",
    "CVE-2009-3883",
    "CVE-2009-3884",
    "CVE-2009-3885",
    "CVE-2010-0082",
    "CVE-2010-0084",
    "CVE-2010-0085",
    "CVE-2010-0088",
    "CVE-2010-0091",
    "CVE-2010-0092",
    "CVE-2010-0093",
    "CVE-2010-0094",
    "CVE-2010-0095",
    "CVE-2010-0837",
    "CVE-2010-0838",
    "CVE-2010-0840",
    "CVE-2010-0845",
    "CVE-2010-0847",
    "CVE-2010-0848"
  );
  script_bugtraq_id(
    36881,
    36935,
    39065,
    39069,
    39071,
    39072,
    39075,
    39078,
    39081,
    39085,
    39086,
    39088,
    39089,
    39090,
    39093,
    39094,
    39096
  );
  script_osvdb_id(
    56752,
    59705,
    59706,
    59707,
    59708,
    59709,
    59710,
    59714,
    59915,
    59916,
    59917,
    59918,
    59919,
    59920,
    59921,
    59922,
    61784,
    63481,
    63482,
    63483,
    63484,
    63485,
    63486,
    63487,
    63488,
    63489,
    63498,
    63499,
    63500,
    63503,
    63504,
    63505
  );
  script_xref(name:"MDVSA", value:"2010:084");

  script_name(english:"Mandriva Linux Security Advisory : java-1.6.0-openjdk (MDVSA-2010:084)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple Java OpenJDK security vulnerabilities has been identified and
fixed :

  - TLS: MITM attacks via session renegotiation
    (CVE-2009-3555).

    - Loader-constraint table allows arrays instead of only
      the b ase-classes (CVE-2010-0082).

  - Policy/PolicyFile leak dynamic ProtectionDomains.
    (CVE-2010-0084).

    - File TOCTOU deserialization vulnerability
      (CVE-2010-0085).

    - Inflater/Deflater clone issues (CVE-2010-0088).

    - Unsigned applet can retrieve the dragged information
      before drop action occurs (CVE-2010-0091).

  - AtomicReferenceArray causes SIGSEGV -> SEGV_MAPERR error
    (CVE-2010-0092).

  - System.arraycopy unable to reference elements beyond
    Integer.MAX_VALUE bytes (CVE-2010-0093).

  - Deserialization of RMIConnectionImpl objects should
    enforce stricter checks (CVE-2010-0094).

  - Subclasses of InetAddress may incorrectly interpret
    network addresses (CVE-2010-0095).

  - JAR unpack200 must verify input parameters
    (CVE-2010-0837).

    - CMM readMabCurveData Buffer Overflow Vulnerability
      (CVE-2010-0838).

    - Applet Trusted Methods Chaining Privilege Escalation
      Vulnerability (CVE-2010-0840).

  - No ClassCastException for HashAttributeSet constructors
    if run with -Xcomp (CVE-2010-0845)

  - ImagingLib arbitrary code execution vulnerability
    (CVE-2010-0847).

    - AWT Library Invalid Index Vulnerability
      (CVE-2010-0848).

Additional security issues that was fixed with IcedTea6 1.6.2 :

  - deprecate MD2 in SSL cert validation (CVE-2009-2409).

    - ICC_Profile file existence detection information leak
      (CVE-2009-3728).

  - JRE AWT setDifflCM stack overflow (CVE-2009-3869).

    - JRE AWT setBytePixels heap overflow (CVE-2009-3871).

    - JPEG Image Writer quantization problem
      (CVE-2009-3873).

    - ImageI/O JPEG heap overflow (CVE-2009-3874).

    - MessageDigest.isEqual introduces timing attack
      vulnerabilities (CVE-2009-3875).

  - OpenJDK ASN.1/DER input stream parser denial of service
    (CVE-2009-3876, CVE-2009-3877)

  - GraphicsConfiguration information leak (CVE-2009-3879).

    - UI logging information leakage (CVE-2009-3880).

    - resurrected classloaders can still have children
      (CVE-2009-3881).

    - Numerous static security flaws in Swing (findbugs)
      (CVE-2009-3882).

    - Mutable statics in Windows PL&amp;F (findbugs)
      (CVE-2009-3883).

    - zoneinfo file existence information leak
      (CVE-2009-3884).

    - BMP parsing DoS with UNC ICC links (CVE-2009-3885).

Additionally Paulo Cesar Pereira de Andrade (pcpa) at Mandriva found
and fixed a bug in IcedTea6 1.8 that is also applied to the provided
packages :

  - plugin/icedteanp/IcedTeaNPPlugin.cc
    (plugin_filter_environment): Increment malloc size by
    one to account for NULL terminator. Bug# 474.

Packages for 2009.0 are provided due to the Extended Maintenance
Program."
  );
  # http://article.gmane.org/gmane.comp.java.openjdk.distro-packaging.devel/8938
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5cab9dbb"
  );
  # http://blogs.sun.com/darcy/resource/OpenJDK_6/openjdk6-b18-changes-summary.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c2055f25"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://icedtea.classpath.org/hg/release/icedtea6-1.8/rev/a6a02193b073"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Statement.invoke() Trusted Method Chain Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(22, 119, 189, 200, 264, 310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-1.6.0.0-2.b18.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-demo-1.6.0.0-2.b18.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-devel-1.6.0.0-2.b18.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-2.b18.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-plugin-1.6.0.0-2.b18.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-src-1.6.0.0-2.b18.2mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.1", reference:"java-1.6.0-openjdk-1.6.0.0-2.b18.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"java-1.6.0-openjdk-demo-1.6.0.0-2.b18.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"java-1.6.0-openjdk-devel-1.6.0.0-2.b18.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-2.b18.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"java-1.6.0-openjdk-plugin-1.6.0.0-2.b18.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"java-1.6.0-openjdk-src-1.6.0.0-2.b18.2mdv2009.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.0", reference:"java-1.6.0-openjdk-1.6.0.0-2.b18.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"java-1.6.0-openjdk-demo-1.6.0.0-2.b18.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"java-1.6.0-openjdk-devel-1.6.0.0-2.b18.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-2.b18.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"java-1.6.0-openjdk-plugin-1.6.0.0-2.b18.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"java-1.6.0-openjdk-src-1.6.0.0-2.b18.2mdv2010.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
