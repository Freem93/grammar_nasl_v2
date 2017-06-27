#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60691);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2009-2409", "CVE-2009-3728", "CVE-2009-3729", "CVE-2009-3865", "CVE-2009-3866", "CVE-2009-3867", "CVE-2009-3868", "CVE-2009-3869", "CVE-2009-3871", "CVE-2009-3872", "CVE-2009-3873", "CVE-2009-3874", "CVE-2009-3875", "CVE-2009-3876", "CVE-2009-3877", "CVE-2009-3879", "CVE-2009-3880", "CVE-2009-3881", "CVE-2009-3882", "CVE-2009-3883", "CVE-2009-3884", "CVE-2009-3886");

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
"CVE-2009-2409 deprecate MD2 in SSL cert validation (Kaminsky)

CVE-2009-3873 OpenJDK JPEG Image Writer quantization problem (6862968)

CVE-2009-3875 OpenJDK MessageDigest.isEqual introduces timing attack
vulnerabilities (6863503)

CVE-2009-3876 OpenJDK ASN.1/DER input stream parser denial of service
(6864911) CVE-2009-3877

CVE-2009-3869 OpenJDK JRE AWT setDifflCM stack overflow (6872357)

CVE-2009-3871 OpenJDK JRE AWT setBytePixels heap overflow (6872358)

CVE-2009-3874 OpenJDK ImageI/O JPEG heap overflow (6874643)

CVE-2009-3728 OpenJDK ICC_Profile file existence detection information
leak (6631533)

CVE-2009-3881 OpenJDK resurrected classloaders can still have children
(6636650)

CVE-2009-3882 CVE-2009-3883 OpenJDK information leaks in mutable
variables (6657026,6657138)

CVE-2009-3880 OpenJDK UI logging information leakage(6664512)

CVE-2009-3879 OpenJDK GraphicsConfiguration information leak(6822057)

CVE-2009-3884 OpenJDK zoneinfo file existence information leak
(6824265)

CVE-2009-3729 JRE TrueType font parsing crash (6815780)

CVE-2009-3872 JRE JPEG JFIF Decoder issue (6862969)

CVE-2009-3886 JRE REGRESSION:have problem to run JNLP app and applets
with signed Jar files (6870531)

CVE-2009-3865 java-1.6.0-sun: ACE in JRE Deployment Toolkit (6869752)

CVE-2009-3866 java-1.6.0-sun: Privilege escalation in the Java Web
Start Installer (6872824)

CVE-2009-3867 java-1.5.0-sun, java-1.6.0-sun: Stack-based buffer
overflow via a long file: URL argument (6854303)

CVE-2009-3868 java-1.5.0-sun, java-1.6.0-sun: Privilege escalation via
crafted image file due improper color profiles parsing (6862970)

This update fixes several vulnerabilities in the Sun Java 6 Runtime
Environment and the Sun Java 6 Software Development Kit. These
vulnerabilities are summarized on the 'Advance notification of
Security Updates for Java SE' page from Sun Microsystems, listed in
the References section. (CVE-2009-2409, CVE-2009-3728, CVE-2009-3729,

CVE-2009-3865, CVE-2009-3866, CVE-2009-3867, CVE-2009-3868,

CVE-2009-3869, CVE-2009-3871, CVE-2009-3872, CVE-2009-3873,

CVE-2009-3874, CVE-2009-3875, CVE-2009-3876, CVE-2009-3877,

CVE-2009-3879, CVE-2009-3880, CVE-2009-3881, CVE-2009-3882,

CVE-2009-3883, CVE-2009-3884, CVE-2009-3886)

All running instances of Sun Java must be restarted for the update to
take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0911&L=scientific-linux-errata&T=0&P=2369
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c7181e46"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-sun-compat and / or jdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java JRE AWT setDiffICM Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(22, 94, 119, 189, 200, 264, 310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"java-1.6.0-sun-compat-1.6.0.17-1.sl4.jpp")) flag++;
if (rpm_check(release:"SL4", reference:"jdk-1.6.0_17-fcs")) flag++;

if (rpm_check(release:"SL5", cpu:"i386", reference:"java-1.6.0-sun-compat-1.6.0.17-3.sl5.jpp")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"jdk-1.6.0_17-fcs")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
