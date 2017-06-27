#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(94627);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/11/08 17:46:00 $");

  script_cve_id("CVE-2016-5542", "CVE-2016-5554", "CVE-2016-5573", "CVE-2016-5582", "CVE-2016-5597");

  script_name(english:"Scientific Linux Security Update : java-1.7.0-openjdk on SL5.x, SL6.x i386/x86_64");
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
"Security Fix(es) :

  - It was discovered that the Hotspot component of OpenJDK
    did not properly check arguments of the
    System.arraycopy() function in certain cases. An
    untrusted Java application or applet could use this flaw
    to corrupt virtual machine's memory and completely
    bypass Java sandbox restrictions. (CVE-2016-5582)

  - It was discovered that the Hotspot component of OpenJDK
    did not properly check received Java Debug Wire Protocol
    (JDWP) packets. An attacker could possibly use this flaw
    to send debugging commands to a Java program running
    with debugging enabled if they could make victim's
    browser send HTTP requests to the JDWP port of the
    debugged application. (CVE-2016-5573)

  - It was discovered that the Libraries component of
    OpenJDK did not restrict the set of algorithms used for
    Jar integrity verification. This flaw could allow an
    attacker to modify content of the Jar file that used
    weak signing key or hash algorithm. (CVE-2016-5542)

Note: After this update, MD2 hash algorithm and RSA keys with less
than 1024 bits are no longer allowed to be used for Jar integrity
verification by default. MD5 hash algorithm is expected to be disabled
by default in the future updates. A newly introduced security property
jdk.jar.disabledAlgorithms can be used to control the set of disabled
algorithms.

  - A flaw was found in the way the JMX component of OpenJDK
    handled classloaders. An untrusted Java application or
    applet could use this flaw to bypass certain Java
    sandbox restrictions. (CVE-2016-5554)

  - A flaw was found in the way the Networking component of
    OpenJDK handled HTTP proxy authentication. A Java
    application could possibly expose HTTPS server
    authentication credentials via a plain text network
    connection to an HTTP proxy if proxy asked for
    authentication. (CVE-2016-5597)

Note: After this update, Basic HTTP proxy authentication can no longer
be used when tunneling HTTPS connection through an HTTP proxy. Newly
introduced system properties jdk.http.auth.proxying.disabledSchemes
and jdk.http.auth.tunneling.disabledSchemes can be used to control
which authentication schemes can be requested by an HTTP proxy when
proxying HTTP and HTTPS connections respectively."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1611&L=scientific-linux-errata&F=&S=&P=736
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a0650f00"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-1.7.0.121-2.6.8.1.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.121-2.6.8.1.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-demo-1.7.0.121-2.6.8.1.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-devel-1.7.0.121-2.6.8.1.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-javadoc-1.7.0.121-2.6.8.1.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-src-1.7.0.121-2.6.8.1.el5_11")) flag++;

if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-1.7.0.121-2.6.8.1.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.121-2.6.8.1.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-demo-1.7.0.121-2.6.8.1.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-devel-1.7.0.121-2.6.8.1.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-javadoc-1.7.0.121-2.6.8.1.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-src-1.7.0.121-2.6.8.1.el6_8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
