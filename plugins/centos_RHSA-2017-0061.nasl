#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0061 and 
# CentOS Errata and Security Advisory 2017:0061 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(96457);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/01/17 14:52:07 $");

  script_cve_id("CVE-2016-5542", "CVE-2016-5554", "CVE-2016-5573", "CVE-2016-5582", "CVE-2016-5597");
  script_osvdb_id(145946, 145947, 145948, 145949, 145950);
  script_xref(name:"RHSA", value:"2017:0061");

  script_name(english:"CentOS 5 / 6 / 7 : java-1.6.0-openjdk (CESA-2017:0061)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for java-1.6.0-openjdk is now available for Red Hat
Enterprise Linux 5, Red Hat Enterprise Linux 6, and Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The java-1.6.0-openjdk packages provide the OpenJDK 6 Java Runtime
Environment and the OpenJDK 6 Java Software Development Kit.

Security Fix(es) :

* It was discovered that the Hotspot component of OpenJDK did not
properly check arguments of the System.arraycopy() function in certain
cases. An untrusted Java application or applet could use this flaw to
corrupt virtual machine's memory and completely bypass Java sandbox
restrictions. (CVE-2016-5582)

* It was discovered that the Hotspot component of OpenJDK did not
properly check received Java Debug Wire Protocol (JDWP) packets. An
attacker could possibly use this flaw to send debugging commands to a
Java program running with debugging enabled if they could make
victim's browser send HTTP requests to the JDWP port of the debugged
application. (CVE-2016-5573)

* It was discovered that the Libraries component of OpenJDK did not
restrict the set of algorithms used for Jar integrity verification.
This flaw could allow an attacker to modify content of the Jar file
that used weak signing key or hash algorithm. (CVE-2016-5542)

Note: After this update, MD2 hash algorithm and RSA keys with less
than 1024 bits are no longer allowed to be used for Jar integrity
verification by default. MD5 hash algorithm is expected to be disabled
by default in the future updates. A newly introduced security property
jdk.jar.disabledAlgorithms can be used to control the set of disabled
algorithms.

* A flaw was found in the way the JMX component of OpenJDK handled
classloaders. An untrusted Java application or applet could use this
flaw to bypass certain Java sandbox restrictions. (CVE-2016-5554)

* A flaw was found in the way the Networking component of OpenJDK
handled HTTP proxy authentication. A Java application could possibly
expose HTTPS server authentication credentials via a plain text
network connection to an HTTP proxy if proxy asked for authentication.
(CVE-2016-5597)

Note: After this update, Basic HTTP proxy authentication can no longer
be used when tunneling HTTPS connection through an HTTP proxy. Newly
introduced system properties jdk.http.auth.proxying.disabledSchemes
and jdk.http.auth.tunneling.disabledSchemes can be used to control
which authentication schemes can be requested by an HTTP proxy when
proxying HTTP and HTTPS connections respectively."
  );
  # http://lists.centos.org/pipermail/centos-announce/2017-January/022207.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8ea51b01"
  );
  # http://lists.centos.org/pipermail/centos-announce/2017-January/022209.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?54c3d8d2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2017-January/022210.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dc42e136"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-1.6.0.41-1.13.13.1.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-demo-1.6.0.41-1.13.13.1.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-devel-1.6.0.41-1.13.13.1.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-javadoc-1.6.0.41-1.13.13.1.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-src-1.6.0.41-1.13.13.1.el5_11")) flag++;

if (rpm_check(release:"CentOS-6", reference:"java-1.6.0-openjdk-1.6.0.41-1.13.13.1.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.6.0-openjdk-demo-1.6.0.41-1.13.13.1.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.6.0-openjdk-devel-1.6.0.41-1.13.13.1.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.6.0-openjdk-javadoc-1.6.0.41-1.13.13.1.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.6.0-openjdk-src-1.6.0.41-1.13.13.1.el6_8")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.6.0-openjdk-1.6.0.41-1.13.13.1.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.6.0-openjdk-demo-1.6.0.41-1.13.13.1.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.6.0-openjdk-devel-1.6.0.41-1.13.13.1.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.6.0-openjdk-javadoc-1.6.0.41-1.13.13.1.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.6.0-openjdk-src-1.6.0.41-1.13.13.1.el7_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
