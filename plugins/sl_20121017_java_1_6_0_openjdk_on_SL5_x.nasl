#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(62617);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/11/18 19:12:04 $");

  script_cve_id("CVE-2012-3216", "CVE-2012-4416", "CVE-2012-5068", "CVE-2012-5069", "CVE-2012-5071", "CVE-2012-5072", "CVE-2012-5073", "CVE-2012-5075", "CVE-2012-5077", "CVE-2012-5079", "CVE-2012-5081", "CVE-2012-5084", "CVE-2012-5085", "CVE-2012-5086", "CVE-2012-5089");

  script_name(english:"Scientific Linux Security Update : java-1.6.0-openjdk on SL5.x i386/x86_64");
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
"Multiple improper permission check issues were discovered in the
Beans, Swing, and JMX components in OpenJDK. An untrusted Java
application or applet could use these flaws to bypass Java sandbox
restrictions. (CVE-2012-5086, CVE-2012-5084, CVE-2012-5089)

Multiple improper permission check issues were discovered in the
Scripting, JMX, Concurrency, Libraries, and Security components in
OpenJDK. An untrusted Java application or applet could use these flaws
to bypass certain Java sandbox restrictions. (CVE-2012-5068,
CVE-2012-5071, CVE-2012-5069, CVE-2012-5073, CVE-2012-5072)

It was discovered that java.util.ServiceLoader could create an
instance of an incompatible class while performing provider lookup. An
untrusted Java application or applet could use this flaw to bypass
certain Java sandbox restrictions. (CVE-2012-5079)

It was discovered that the Java Secure Socket Extension (JSSE) SSL/TLS
implementation did not properly handle handshake records containing an
overly large data length value. An unauthenticated, remote attacker
could possibly use this flaw to cause an SSL/TLS server to terminate
with an exception. (CVE-2012-5081)

It was discovered that the JMX component in OpenJDK could perform
certain actions in an insecure manner. An untrusted Java application
or applet could possibly use this flaw to disclose sensitive
information. (CVE-2012-5075)

A bug in the Java HotSpot Virtual Machine optimization code could
cause it to not perform array initialization in certain cases. An
untrusted Java application or applet could use this flaw to disclose
portions of the virtual machine's memory. (CVE-2012-4416)

It was discovered that the SecureRandom class did not properly protect
against the creation of multiple seeders. An untrusted Java
application or applet could possibly use this flaw to disclose
sensitive information. (CVE-2012-5077)

It was discovered that the java.io.FilePermission class exposed the
hash code of the canonicalized path name. An untrusted Java
application or applet could possibly use this flaw to determine
certain system paths, such as the current working directory.
(CVE-2012-3216)

This update disables Gopher protocol support in the java.net package
by default. Gopher support can be enabled by setting the newly
introduced property, 'jdk.net.registerGopherProtocol', to true.
(CVE-2012-5085)

This erratum also upgrades the OpenJDK package to IcedTea6 1.10.10. .
All running instances of OpenJDK Java must be restarted for the update
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1210&L=scientific-linux-errata&T=0&P=2536
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?73ec6646"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/18");
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
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-1.6.0.0-1.28.1.10.10.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.28.1.10.10.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.28.1.10.10.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.28.1.10.10.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-src-1.6.0.0-1.28.1.10.10.el5_8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
