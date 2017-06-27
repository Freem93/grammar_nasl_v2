#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41408);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/10/25 23:46:55 $");

  script_cve_id("CVE-2009-2670", "CVE-2009-2671", "CVE-2009-2672", "CVE-2009-2673", "CVE-2009-2674", "CVE-2009-2675", "CVE-2009-2676");

  script_name(english:"SuSE 11 Security Update : Sun Java 1.6.0 (SAT Patch Number 1163)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Sun Java JRE /JDK 6 was updated to Update 15 fixing various
security issues.

  - The audio system in Sun Java Runtime Environment (JRE)
    in JDK and JRE 6 before Update 15, and JDK and JRE 5.0
    before Update 20, does not prevent access to
    java.lang.System properties by (1) untrusted applets and
    (2) Java Web Start applications, which allows
    context-dependent attackers to obtain sensitive
    information by reading these properties. (CVE-2009-2670)

  - The SOCKS proxy implementation in Sun Java Runtime
    Environment (JRE) in JDK and JRE 6 before Update 15, and
    JDK and JRE 5.0 before Update 20, allows remote
    attackers to discover the username of the account that
    invoked an untrusted (1) applet or (2) Java Web Start
    application via unspecified vectors. (CVE-2009-2671)

  - The proxy mechanism implementation in Sun Java Runtime
    Environment (JRE) in JDK and JRE 6 before Update 15, and
    JDK and JRE 5.0 before Update 20, does not prevent
    access to browser cookies by untrusted (1) applets and
    (2) Java Web Start applications, which allows remote
    attackers to hijack web sessions via unspecified
    vectors. (CVE-2009-2672)

  - The proxy mechanism implementation in Sun Java Runtime
    Environment (JRE) in JDK and JRE 6 before Update 15, and
    JDK and JRE 5.0 before Update 20, allows remote
    attackers to bypass intended access restrictions and
    connect to arbitrary sites via unspecified vectors,
    related to a declaration that lacks the final keyword.
    (CVE-2009-2673)

  - Integer overflow in Sun Java Runtime Environment (JRE)
    in JDK and JRE 6 before Update 15 allows
    context-dependent attackers to gain privileges via
    vectors involving an untrusted Java Web Start
    application that grants permissions to itself, related
    to parsing of JPEG images. (CVE-2009-2674)

  - Integer overflow in the unpack200 utility in Sun Java
    Runtime Environment (JRE) in JDK and JRE 6 before Update
    15, and JDK and JRE 5.0 before Update 20, allows
    context-dependent attackers to gain privileges via
    vectors involving an untrusted (1) applet or (2) Java
    Web Start application that grants permissions to itself,
    related to decompression. (CVE-2009-2675)

  - Unspecified vulnerability in JNLPAppletlauncher in Sun
    Java SE, and SE for Business, in JDK and JRE 6 Update 14
    and earlier +and JDK and JRE 5.0 Update 19 and earlier;
    and Java SE for Business in SDK and JRE 1.4.2_21 and
    earlier; allows remote attackers to create or modify
    arbitrary files via vectors involving an untrusted Java
    applet. (CVE-2009-2676)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=492912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=494536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=496489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=510016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=528268"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2670.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2671.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2672.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2673.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2674.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2675.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2676.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 1163.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-sun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-sun-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-sun-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-sun-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-sun-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-sun-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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
if (pl) audit(AUDIT_OS_NOT, "SuSE 11.0");


flag = 0;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"java-1_6_0-sun-1.6.0.u15-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"java-1_6_0-sun-alsa-1.6.0.u15-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"java-1_6_0-sun-demo-1.6.0.u15-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"java-1_6_0-sun-jdbc-1.6.0.u15-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"java-1_6_0-sun-plugin-1.6.0.u15-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"java-1_6_0-sun-src-1.6.0.u15-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"java-1_6_0-sun-1.6.0.u15-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"java-1_6_0-sun-alsa-1.6.0.u15-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"java-1_6_0-sun-demo-1.6.0.u15-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"java-1_6_0-sun-jdbc-1.6.0.u15-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"java-1_6_0-sun-plugin-1.6.0.u15-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"java-1_6_0-sun-src-1.6.0.u15-0.1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
