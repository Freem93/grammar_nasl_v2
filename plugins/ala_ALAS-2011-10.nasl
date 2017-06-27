#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2011-10.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(69569);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/22 14:14:48 $");

  script_cve_id("CVE-2011-3389", "CVE-2011-3521", "CVE-2011-3544", "CVE-2011-3547", "CVE-2011-3548", "CVE-2011-3551", "CVE-2011-3552", "CVE-2011-3553", "CVE-2011-3554", "CVE-2011-3556", "CVE-2011-3557", "CVE-2011-3558", "CVE-2011-3560");
  script_xref(name:"ALAS", value:"2011-10");
  script_xref(name:"RHSA", value:"2011:1380");

  script_name(english:"Amazon Linux AMI : java-1.6.0-openjdk (ALAS-2011-10) (BEAST)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was found in the Java RMI (Remote Method Invocation) registry
implementation. A remote RMI client could use this flaw to execute
arbitrary code on the RMI server running the registry. (CVE-2011-3556)

A flaw was found in the Java RMI registry implementation. A remote RMI
client could use this flaw to execute code on the RMI server with
unrestricted privileges. (CVE-2011-3557)

A flaw was found in the IIOP (Internet Inter-Orb Protocol)
deserialization code. An untrusted Java application or applet running
in a sandbox could use this flaw to bypass sandbox restrictions by
deserializing specially crafted input. (CVE-2011-3521)

It was found that the Java ScriptingEngine did not properly restrict
the privileges of sandboxed applications. An untrusted Java
application or applet running in a sandbox could use this flaw to
bypass sandbox restrictions. (CVE-2011-3544)

A flaw was found in the AWTKeyStroke implementation. An untrusted Java
application or applet running in a sandbox could use this flaw to
bypass sandbox restrictions. (CVE-2011-3548)

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the Java2D code used to perform transformations of graphic
shapes and images. An untrusted Java application or applet running in
a sandbox could use this flaw to bypass sandbox restrictions.
(CVE-2011-3551)

An insufficient error checking flaw was found in the unpacker for JAR
files in pack200 format. A specially crafted JAR file could use this
flaw to crash the Java Virtual Machine (JVM) or, possibly, execute
arbitrary code with JVM privileges. (CVE-2011-3554)

It was found that HttpsURLConnection did not perform SecurityManager
checks in the setSSLSocketFactory method. An untrusted Java
application or applet running in a sandbox could use this flaw to
bypass connection restrictions defined in the policy. (CVE-2011-3560)

A flaw was found in the way the SSL 3 and TLS 1.0 protocols used block
ciphers in cipher-block chaining (CBC) mode. An attacker able to
perform a chosen plain text attack against a connection mixing trusted
and untrusted data could use this flaw to recover portions of the
trusted data sent over the connection. (CVE-2011-3389)

Note: This update mitigates the CVE-2011-3389 issue by splitting the
first application data record byte to a separate SSL/TLS protocol
record. This mitigation may cause compatibility issues with some
SSL/TLS implementations and can be disabled using the
jsse.enableCBCProtection boolean property. This can be done on the
command line by appending the flag '-Djsse.enableCBCProtection=false'
to the java command.

An information leak flaw was found in the InputStream.skip
implementation. An untrusted Java application or applet could possibly
use this flaw to obtain bytes skipped by other threads.
(CVE-2011-3547)

A flaw was found in the Java HotSpot virtual machine. An untrusted
Java application or applet could use this flaw to disclose portions of
the VM memory, or cause it to crash. (CVE-2011-3558)

The Java API for XML Web Services (JAX-WS) implementation in OpenJDK
was configured to include the stack trace in error messages sent to
clients. A remote client could possibly use this flaw to obtain
sensitive information. (CVE-2011-3553)

It was found that Java applications running with SecurityManager
restrictions were allowed to use too many UDP sockets by default. If
multiple instances of a malicious application were started at the same
time, they could exhaust all available UDP sockets on the system.
(CVE-2011-3552)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2011-10.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update java-1.6.0-openjdk' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Rhino Script Engine Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/31");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/AmazonLinux/release")) audit(AUDIT_OS_NOT, "Amazon Linux AMI");
if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-1.6.0.0-52.1.9.10.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-debuginfo-1.6.0.0-52.1.9.10.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-demo-1.6.0.0-52.1.9.10.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-devel-1.6.0.0-52.1.9.10.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-52.1.9.10.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-src-1.6.0.0-52.1.9.10.40.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-openjdk / java-1.6.0-openjdk-debuginfo / etc");
}
