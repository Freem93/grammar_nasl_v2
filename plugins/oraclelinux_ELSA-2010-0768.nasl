#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0768 and 
# Oracle Linux Security Advisory ELSA-2010-0768 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68117);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/20 14:21:43 $");

  script_cve_id("CVE-2009-3555", "CVE-2010-3541", "CVE-2010-3548", "CVE-2010-3549", "CVE-2010-3551", "CVE-2010-3553", "CVE-2010-3554", "CVE-2010-3557", "CVE-2010-3561", "CVE-2010-3562", "CVE-2010-3564", "CVE-2010-3565", "CVE-2010-3567", "CVE-2010-3568", "CVE-2010-3569", "CVE-2010-3573", "CVE-2010-3574");
  script_bugtraq_id(36935, 43963, 43979, 43985, 43992, 43994, 44009, 44011, 44012, 44013, 44014, 44016, 44017, 44027, 44028, 44032, 44035);
  script_xref(name:"RHSA", value:"2010:0768");

  script_name(english:"Oracle Linux 5 : java-1.6.0-openjdk (ELSA-2010-0768)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0768 :

Updated java-1.6.0-openjdk packages that fix several security issues
and two bugs are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

These packages provide the OpenJDK 6 Java Runtime Environment and the
OpenJDK 6 Software Development Kit.

defaultReadObject of the Serialization API could be tricked into
setting a volatile field multiple times, which could allow a remote
attacker to execute arbitrary code with the privileges of the user
running the applet or application. (CVE-2010-3569)

Race condition in the way objects were deserialized could allow an
untrusted applet or application to misuse the privileges of the user
running the applet or application. (CVE-2010-3568)

Miscalculation in the OpenType font rendering implementation caused
out-of-bounds memory access, which could allow remote attackers to
execute code with the privileges of the user running the java process.
(CVE-2010-3567)

JPEGImageWriter.writeImage in the imageio API improperly checked
certain image metadata, which could allow a remote attacker to execute
arbitrary code in the context of the user running the applet or
application. (CVE-2010-3565)

Double free in IndexColorModel could cause an untrusted applet or
application to crash or, possibly, execute arbitrary code with the
privileges of the user running the applet or application.
(CVE-2010-3562)

The privileged accept method of the ServerSocket class in the Common
Object Request Broker Architecture (CORBA) implementation in OpenJDK
allowed it to receive connections from any host, instead of just the
host of the current connection. An attacker could use this flaw to
bypass restrictions defined by network permissions. (CVE-2010-3561)

Flaws in the Swing library could allow an untrusted application to
modify the behavior and state of certain JDK classes. (CVE-2010-3557)

Flaws in the CORBA implementation could allow an attacker to execute
arbitrary code by misusing permissions granted to certain system
objects. (CVE-2010-3554)

UIDefault.ProxyLazyValue had unsafe reflection usage, allowing
untrusted callers to create objects via ProxyLazyValue values.
(CVE-2010-3553)

HttpURLConnection improperly handled the 'chunked' transfer encoding
method, which could allow remote attackers to conduct HTTP response
splitting attacks. (CVE-2010-3549)

HttpURLConnection improperly checked whether the calling code was
granted the 'allowHttpTrace' permission, allowing untrusted code to
create HTTP TRACE requests. (CVE-2010-3574)

HttpURLConnection did not validate request headers set by applets,
which could allow remote attackers to trigger actions otherwise
restricted to HTTP clients. (CVE-2010-3541, CVE-2010-3573)

The Kerberos implementation improperly checked the sanity of AP-REQ
requests, which could cause a denial of service condition in the
receiving Java Virtual Machine. (CVE-2010-3564)

The RHSA-2010:0339 update mitigated a man-in-the-middle attack in the
way the TLS/SSL (Transport Layer Security/Secure Sockets Layer)
protocols handle session renegotiation by disabling renegotiation.
This update implements the TLS Renegotiation Indication Extension as
defined in RFC 5746, allowing secure renegotiation between updated
clients and servers. (CVE-2009-3555)

The NetworkInterface class improperly checked the network 'connect'
permissions for local network addresses, which could allow remote
attackers to read local network addresses. (CVE-2010-3551)

Information leak flaw in the Java Naming and Directory Interface
(JNDI) could allow a remote attacker to access information about
otherwise-protected internal network names. (CVE-2010-3548)

Note: Flaws concerning applets in this advisory (CVE-2010-3568,
CVE-2010-3554, CVE-2009-3555, CVE-2010-3562, CVE-2010-3557,
CVE-2010-3548, CVE-2010-3564, CVE-2010-3565, CVE-2010-3569) can only
be triggered in OpenJDK by calling the 'appletviewer' application.

Bug fixes :

* This update provides one defense in depth patch. (BZ#639922)

* Problems for certain SSL connections. In a reported case, this
prevented the JBoss JAAS modules from connecting over SSL to Microsoft
Active Directory servers. (BZ#618290)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-October/001689.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-1.6.0.0-1.16.b17.0.1.el5")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.16.b17.0.1.el5")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.16.b17.0.1.el5")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.16.b17.0.1.el5")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-src-1.6.0.0-1.16.b17.0.1.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-openjdk / java-1.6.0-openjdk-demo / etc");
}
