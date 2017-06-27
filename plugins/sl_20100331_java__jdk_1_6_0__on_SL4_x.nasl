#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60777);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/11/18 01:30:19 $");

  script_cve_id("CVE-2009-3555", "CVE-2010-0082", "CVE-2010-0084", "CVE-2010-0085", "CVE-2010-0087", "CVE-2010-0088", "CVE-2010-0089", "CVE-2010-0090", "CVE-2010-0091", "CVE-2010-0092", "CVE-2010-0093", "CVE-2010-0094", "CVE-2010-0095", "CVE-2010-0837", "CVE-2010-0838", "CVE-2010-0839", "CVE-2010-0840", "CVE-2010-0841", "CVE-2010-0842", "CVE-2010-0843", "CVE-2010-0844", "CVE-2010-0845", "CVE-2010-0846", "CVE-2010-0847", "CVE-2010-0848", "CVE-2010-0849");

  script_name(english:"Scientific Linux Security Update : java (jdk 1.6.0) on SL4.x, SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2009-3555 TLS: MITM attacks via session renegotiation

CVE-2010-0082 OpenJDK Loader-constraint table allows arrays instead of
only the base-classes (6626217)

CVE-2010-0084 OpenJDK Policy/PolicyFile leak dynamic
ProtectionDomains. (6633872)

CVE-2010-0085 OpenJDK File TOCTOU deserialization vulnerability
(6736390)

CVE-2010-0088 OpenJDK Inflater/Deflater clone issues (6745393)

CVE-2010-0091 OpenJDK Unsigned applet can retrieve the dragged
information before drop action occurs(6887703)

CVE-2010-0092 OpenJDK AtomicReferenceArray causes SIGSEGV ->
SEGV_MAPERR error (6888149)

CVE-2010-0093 OpenJDK System.arraycopy unable to reference elements
beyond Integer.MAX_VALUE bytes (6892265)

CVE-2010-0094 OpenJDK Deserialization of RMIConnectionImpl objects
should enforce stricter checks (6893947)

CVE-2010-0095 OpenJDK Subclasses of InetAddress may incorrectly
interpret network addresses (6893954)

CVE-2010-0845 OpenJDK No ClassCastException for HashAttributeSet
constructors if run with -Xcomp (6894807)

CVE-2010-0838 OpenJDK CMM readMabCurveData Buffer Overflow
Vulnerability (6899653)

CVE-2010-0837 OpenJDK JAR 'unpack200' must verify input parameters
(6902299)

CVE-2010-0840 OpenJDK Applet Trusted Methods Chaining Privilege
Escalation Vulnerability (6904691)

CVE-2010-0841 OpenJDK JPEGImageReader stepX Integer Overflow
Vulnerability (6909597)

CVE-2010-0848 OpenJDK AWT Library Invalid Index Vulnerability
(6914823)

CVE-2010-0847 OpenJDK ImagingLib arbitrary code execution
vulnerability (6914866)

CVE-2010-0846 JDK unspecified vulnerability in ImageIO component

CVE-2010-0849 JDK unspecified vulnerability in Java2D component

CVE-2010-0087 JDK unspecified vulnerability in JWS/Plugin component

CVE-2010-0839 CVE-2010-0842 CVE-2010-0843 CVE-2010-0844 JDK multiple
unspecified vulnerabilities

CVE-2010-0090 JDK unspecified vulnerability in JavaWS/Plugin component

CVE-2010-0089 JDK unspecified vulnerability in JavaWS/Plugin component

This update fixes several vulnerabilities in the Sun Java 6 Runtime
Environment and the Sun Java 6 Software Development Kit. Further
information about these flaws can be found on the 'Oracle Java SE and
Java for Business Critical Patch Update Advisory' page, listed in the
References section. (CVE-2009-3555, CVE-2010-0082, CVE-2010-0084,

CVE-2010-0085, CVE-2010-0087, CVE-2010-0088, CVE-2010-0089,

CVE-2010-0090, CVE-2010-0091, CVE-2010-0092, CVE-2010-0093,

CVE-2010-0094, CVE-2010-0095, CVE-2010-0837, CVE-2010-0838,

CVE-2010-0839, CVE-2010-0840, CVE-2010-0841, CVE-2010-0842,

CVE-2010-0843, CVE-2010-0844, CVE-2010-0845, CVE-2010-0846,

CVE-2010-0847, CVE-2010-0848, CVE-2010-0849)

For the CVE-2009-3555 issue, this update disables renegotiation in the
Java Secure Socket Extension (JSSE) component. Unsafe renegotiation
can be re-enabled using the sun.security.ssl.allowUnsafeRenegotiation
property.

All running instances of Sun Java must be restarted for the update to
take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1004&L=scientific-linux-errata&T=0&P=1274
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a2daac03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-sun-compat and / or jdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java MixerSequencer Object GM_Song Structure Handling Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL4", reference:"java-1.6.0-sun-compat-1.6.0.19-1.sl4.jpp")) flag++;
if (rpm_check(release:"SL4", reference:"jdk-1.6.0_19-fcs")) flag++;

if (rpm_check(release:"SL5", reference:"java-1.6.0-sun-compat-1.6.0.19-1.sl5.jpp")) flag++;
if (rpm_check(release:"SL5", reference:"jdk-1.6.0_19-fcs")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
