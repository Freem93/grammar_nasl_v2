#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61264);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/13 15:30:40 $");

  script_cve_id("CVE-2011-3563", "CVE-2011-3571", "CVE-2011-5035", "CVE-2012-0497", "CVE-2012-0501", "CVE-2012-0502", "CVE-2012-0503", "CVE-2012-0505", "CVE-2012-0506");

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
"These packages provide the OpenJDK 6 Java Runtime Environment and the
OpenJDK 6 Software Development Kit.

It was discovered that Java2D did not properly check graphics
rendering objects before passing them to the native renderer.
Malicious input, or an untrusted Java application or applet could use
this flaw to crash the Java Virtual Machine (JVM), or bypass Java
sandbox restrictions. (CVE-2012-0497)

It was discovered that the exception thrown on deserialization failure
did not always contain a proper identification of the cause of the
failure. An untrusted Java application or applet could use this flaw
to bypass Java sandbox restrictions. (CVE-2012-0505)

The AtomicReferenceArray class implementation did not properly check
if the array was of the expected Object[] type. A malicious Java
application or applet could use this flaw to bypass Java sandbox
restrictions. (CVE-2011-3571)

It was discovered that the use of TimeZone.setDefault() was not
restricted by the SecurityManager, allowing an untrusted Java
application or applet to set a new default time zone, and hence bypass
Java sandbox restrictions. (CVE-2012-0503)

The HttpServer class did not limit the number of headers read from
HTTP requests. A remote attacker could use this flaw to make an
application using HttpServer use an excessive amount of CPU time via a
specially crafted request. This update introduces a header count limit
controlled using the sun.net.httpserver.maxReqHeaders property. The
default value is 200. (CVE-2011-5035)

The Java Sound component did not properly check buffer boundaries.
Malicious input, or an untrusted Java application or applet could use
this flaw to cause the Java Virtual Machine (JVM) to crash or disclose
a portion of its memory. (CVE-2011-3563)

A flaw was found in the AWT KeyboardFocusManager that could allow an
untrusted Java application or applet to acquire keyboard focus and
possibly steal sensitive information. (CVE-2012-0502)

It was discovered that the CORBA (Common Object Request Broker
Architecture) implementation in Java did not properly protect
repository identifiers on certain CORBA objects. This could have been
used to modify immutable object data. (CVE-2012-0506)

An off-by-one flaw, causing a stack overflow, was found in the
unpacker for ZIP files. A specially crafted ZIP archive could cause
the Java Virtual Machine (JVM) to crash when opened. (CVE-2012-0501)

This erratum also upgrades the OpenJDK package to IcedTea6 1.10.6.

All users of java-1.6.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1202&L=scientific-linux-errata&T=0&P=4167
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3acfeb2d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-1.6.0.0-1.25.1.10.6.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-debuginfo-1.6.0.0-1.25.1.10.6.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.25.1.10.6.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.25.1.10.6.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.25.1.10.6.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-src-1.6.0.0-1.25.1.10.6.el5_8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
