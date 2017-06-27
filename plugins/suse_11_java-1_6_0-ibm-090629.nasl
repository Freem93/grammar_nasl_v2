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
  script_id(41406);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/21 20:21:20 $");

  script_cve_id("CVE-2009-1093", "CVE-2009-1094", "CVE-2009-1095", "CVE-2009-1096", "CVE-2009-1097", "CVE-2009-1098", "CVE-2009-1099", "CVE-2009-1100", "CVE-2009-1101", "CVE-2009-1103", "CVE-2009-1104", "CVE-2009-1105", "CVE-2009-1106", "CVE-2009-1107");

  script_name(english:"SuSE 11 Security Update : IBM Java 1.6.0 (SAT Patch Number 1058)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"IBM Java 6 SR 5 was released fixing various bugs and critical security
issues :

  - A vulnerability in the Java Runtime Environment (JRE)
    with initializing LDAP connections may be exploited by a
    remote client to cause a denial-of-service condition on
    the LDAP service. (CVE-2009-1093)

  - A vulnerability in Java Runtime Environment LDAP client
    implementation may allow malicious data from an LDAP
    server to cause malicious code to be unexpectedly loaded
    and executed on an LDAP client. (CVE-2009-1094)

  - Buffer overflow vulnerabilities in the Java Runtime
    Environment (JRE) with unpacking applets and Java Web
    Start applications using the unpack200 JAR unpacking
    utility may allow an untrusted applet or application to
    escalate privileges. For example, an untrusted applet
    may grant itself permissions to read and write local
    files or execute local applications that are accessible
    to the user running the untrusted applet. (CVE-2009-1095
    / CVE-2009-1096)

  - A buffer overflow vulnerability in the Java Runtime
    Environment with processing PNG images may allow an
    untrusted Java Web Start application to escalate
    privileges. For example, an untrusted application may
    grant itself permissions to read and write local files
    or execute local applications that are accessible to the
    user running the untrusted application. (CVE-2009-1097)

  - A buffer overflow vulnerability in the Java Runtime
    Environment with processing GIF images may allow an
    untrusted Java Web Start application to escalate
    privileges. For example, an untrusted application may
    grant itself permissions to read and write local files
    or execute local applications that are accessible to the
    user running the untrusted application. (CVE-2009-1097)

  - A buffer overflow vulnerability in the Java Runtime
    Environment with processing GIF images may allow an
    untrusted applet or Java Web Start application to
    escalate privileges. For example, an untrusted applet
    may grant itself permissions to read and write local
    files or execute local applications that are accessible
    to the user running the untrusted applet.
    (CVE-2009-1098)

  - A buffer overflow vulnerability in the Java Runtime
    Environment with processing fonts may allow an untrusted
    applet or Java Web Start application to escalate
    privileges. For example, an untrusted applet may grant
    itself permissions to read and write local files or
    execute local applications that are accessible to the
    user running the untrusted applet. (CVE-2009-1099)

  - A vulnerability in the Java Runtime Environment (JRE)
    with storing temporary font files may allow an untrusted
    applet or application to consume a disproportionate
    amount of disk space resulting in a denial-of-service
    condition. (CVE-2009-1100)

  - A vulnerability in the Java Runtime Environment (JRE)
    with processing temporary font files may allow an
    untrusted applet or application to retain temporary
    files resulting in a denial-of-service condition.
    (CVE-2009-1100)

  - A vulnerability in the Java Runtime Environment (JRE)
    HTTP server implementation may allow a remote client to
    create a denial-of-service condition on a JAX-WS service
    endpoint that runs on the JRE. (CVE-2009-1101)

  - A vulnerability in the Java Plug-in with deserializing
    applets may allow an untrusted applet to escalate
    privileges. For example, an untrusted applet may grant
    itself permissions to read and write local files or
    execute local applications that are accessible to the
    user running the untrusted applet. (CVE-2009-1103)

  - The Java Plug-in allows JavaScript code that is loaded
    from the localhost to connect to any port on the system.
    This may be leveraged together with XSS vulnerabilities
    in a blended attack to access other applications
    listening on ports other than the one where the
    JavaScript code was served from. (CVE-2009-1104)

  - The Java Plug-in allows a trusted applet to be launched
    on an earlier version of the Java Runtime Environment
    (JRE) provided the user that downloaded the applet
    allows it to run on the requested release. A
    vulnerability allows JavaScript code that is present in
    the same web page as the applet to exploit known
    vulnerabilities of the requested JRE. (CVE-2009-1105)

  - A vulnerability in the Java Runtime Environment with
    parsing crossdomain.xml files may allow an untrusted
    applet to connect to any site that provides a
    crossdomain.xml file instead of sites that allow the
    domain that the applet is running on. (CVE-2009-1106)

  - The Java Plugin displays a warning dialog for signed
    applets. A signed applet can obscure the contents of the
    dialog and trick a user into trusting the applet.
    (CVE-2009-1107)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=494536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=516361"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1093.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1094.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1095.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1096.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1097.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1098.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1099.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1100.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1101.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1103.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1104.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1105.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1106.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1107.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 1058.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(16, 20, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES11", sp:0, reference:"java-1_6_0-ibm-1.6.0-124.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"java-1_6_0-ibm-fonts-1.6.0-124.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"java-1_6_0-ibm-jdbc-1.6.0-124.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"java-1_6_0-ibm-alsa-1.6.0-124.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"java-1_6_0-ibm-plugin-1.6.0-124.7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
