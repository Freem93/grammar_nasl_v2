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
  script_id(42396);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/10/25 23:46:54 $");

  script_cve_id("CVE-2009-0217", "CVE-2009-2493", "CVE-2009-2625", "CVE-2009-2670", "CVE-2009-2671", "CVE-2009-2672", "CVE-2009-2673", "CVE-2009-2674", "CVE-2009-2675", "CVE-2009-2676");

  script_name(english:"SuSE 11 Security Update : IBM Java 1.6.0 (SAT Patch Number 1497)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The IBM Java 6 JRE/SDK was updated to Service Release 6, fixing
various bugs and security issues.

The following security issues were fixed :

  - A security vulnerability in the JNLPAppletLauncher might
    impact users of the Sun JDK and JRE. Non-current
    versions of the JNLPAppletLauncher might be re-purposed
    with an untrusted Java applet to write arbitrary files
    on the system of the user downloading and running the
    untrusted applet. (CVE-2009-2676)

The JNLPAppletLauncher is a general purpose JNLP-based applet launcher
class for deploying applets that use extension libraries containing
native code.

  - The Java Runtime Environment includes the Java Web Start
    technology that uses the Java Web Start ActiveX control
    to launch Java Web Start in Internet Explorer. A
    security vulnerability in the Active Template Library
    (ATL) in various releases of Microsoft Visual Studio,
    which is used by the Java Web Start ActiveX control,
    might allow the Java Web Start ActiveX control to be
    leveraged to run arbitrary code. This might occur as the
    result of a user of the Java Runtime Environment viewing
    a specially crafted web page that exploits this
    vulnerability. (CVE-2009-2493)

  - A vulnerability in the Java Runtime Environment audio
    system might allow an untrusted applet or Java Web Start
    application to access system properties. (CVE-2009-2670)

  - A vulnerability with verifying HMAC-based XML digital
    signatures in the XML Digital Signature implementation
    included with the Java Runtime Environment (JRE) might
    allow authentication to be bypassed. Applications that
    validate HMAC-based XML digital signatures might be
    vulnerable to this type of attack. (CVE-2009-0217)

Note: This vulnerability cannot be exploited by an untrusted applet or
Java Web Start application.

  - A vulnerability in the Java Runtime Environment with the
    SOCKS proxy implementation might allow an untrusted
    applet or Java Web Start application to determine the
    username of the user running the applet or application.
    (CVE-2009-2671 / CVE-2009-2672)

A second vulnerability in the Java Runtime Environment with the proxy
mechanism implementation might allow an untrusted applet or Java Web
Start application to obtain browser cookies and leverage those cookies
to hijack sessions.

  - A vulnerability in the Java Runtime Environment with the
    proxy mechanism implementation might allow an untrusted
    applet or Java Web Start application to make
    non-authorized socket or URL connections to hosts other
    than the origin host. (CVE-2009-2673)

  - An integer overflow vulnerability in the Java Runtime
    Environment with processing JPEG images might allow an
    untrusted Java Web Start application to escalate
    privileges. For example, an untrusted application might
    grant itself permissions to read and write local files
    or run local applications that are accessible to the
    user running the untrusted applet. (CVE-2009-2674)

  - An integer overflow vulnerability in the Java Runtime
    Environment with unpacking applets and Java Web Start
    applications using the unpack200 JAR unpacking utility
    might allow an untrusted applet or application to
    escalate privileges. For example, an untrusted applet
    might grant itself permissions to read and write local
    files or run local applications that are accessible to
    the user running the untrusted applet. (CVE-2009-2675)

  - A vulnerability in the Java Runtime Environment (JRE)
    with parsing XML data might allow a remote client to
    create a denial-of-service condition on the system that
    the JRE runs on. (CVE-2009-2625)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=548655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0217.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2493.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2625.html"
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
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 1497.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/05");
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
if (rpm_check(release:"SLES11", sp:0, reference:"java-1_6_0-ibm-1.6.0_sr6-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"java-1_6_0-ibm-fonts-1.6.0_sr6-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"java-1_6_0-ibm-jdbc-1.6.0_sr6-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"java-1_6_0-ibm-alsa-1.6.0_sr6-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"java-1_6_0-ibm-plugin-1.6.0_sr6-1.1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
