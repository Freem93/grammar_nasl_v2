#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61329);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/08/16 19:47:28 $");

  script_cve_id("CVE-2012-1711", "CVE-2012-1713", "CVE-2012-1716", "CVE-2012-1717", "CVE-2012-1718", "CVE-2012-1719", "CVE-2012-1723", "CVE-2012-1724", "CVE-2012-1725");

  script_name(english:"Scientific Linux Security Update : java-1.6.0-openjdk on SL6.x i386/x86_64");
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
"These packages provide the OpenJDK 6 Java Runtime Environment and the
OpenJDK 6 Software Development Kit.

Multiple flaws were discovered in the CORBA (Common Object Request
Broker Architecture) implementation in Java. A malicious Java
application or applet could use these flaws to bypass Java sandbox
restrictions or modify immutable object data. (CVE-2012-1711,
CVE-2012-1719)

It was discovered that the SynthLookAndFeel class from Swing did not
properly prevent access to certain UI elements from outside the
current application context. A malicious Java application or applet
could use this flaw to crash the Java Virtual Machine, or bypass Java
sandbox restrictions. (CVE-2012-1716)

Multiple flaws were discovered in the font manager's layout lookup
implementation. A specially crafted font file could cause the Java
Virtual Machine to crash or, possibly, execute arbitrary code with the
privileges of the user running the virtual machine. (CVE-2012-1713)

Multiple flaws were found in the way the Java HotSpot Virtual Machine
verified the bytecode of the class file to be executed. A specially
crafted Java application or applet could use these flaws to crash the
Java Virtual Machine, or bypass Java sandbox restrictions.
(CVE-2012-1723, CVE-2012-1725)

It was discovered that the Java XML parser did not properly handle
certain XML documents. An attacker able to make a Java application
parse a specially crafted XML file could use this flaw to make the XML
parser enter an infinite loop. (CVE-2012-1724)

It was discovered that the Java security classes did not properly
handle Certificate Revocation Lists (CRL). CRL containing entries with
duplicate certificate serial numbers could have been ignored.
(CVE-2012-1718)

It was discovered that various classes of the Java Runtime library
could create temporary files with insecure permissions. A local
attacker could use this flaw to gain access to the content of such
temporary files. (CVE-2012-1717)

Note: If the web browser plug-in provided by the icedtea-web package
was installed, the issues exposed via Java applets could have been
exploited without user interaction if a user visited a malicious
website.

This erratum also upgrades the OpenJDK package to IcedTea6 1.11.3.

All users of java-1.6.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1206&L=scientific-linux-errata&T=0&P=1412
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dd3094fe"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Field Bytecode Verifier Cache Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-1.6.0.0-1.48.1.11.3.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-debuginfo-1.6.0.0-1.48.1.11.3.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.48.1.11.3.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.48.1.11.3.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.48.1.11.3.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-src-1.6.0.0-1.48.1.11.3.el6_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
