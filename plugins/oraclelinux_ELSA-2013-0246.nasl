#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0246 and 
# Oracle Linux Security Advisory ELSA-2013-0246 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68727);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/01/27 16:45:02 $");

  script_cve_id("CVE-2013-0424", "CVE-2013-0425", "CVE-2013-0426", "CVE-2013-0427", "CVE-2013-0428", "CVE-2013-0429", "CVE-2013-0432", "CVE-2013-0433", "CVE-2013-0434", "CVE-2013-0435", "CVE-2013-0440", "CVE-2013-0441", "CVE-2013-0442", "CVE-2013-0443", "CVE-2013-0445", "CVE-2013-0450", "CVE-2013-1475", "CVE-2013-1476", "CVE-2013-1478", "CVE-2013-1480");
  script_osvdb_id(89758, 89759, 89760, 89761, 89762, 89763, 89767, 89769, 89771, 89772, 89786, 89792, 89795, 89796, 89798, 89800, 89801, 89802, 89804, 89806);
  script_xref(name:"RHSA", value:"2013:0246");

  script_name(english:"Oracle Linux 5 : java-1.6.0-openjdk (ELSA-2013-0246)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:0246 :

Updated java-1.6.0-openjdk packages that fix several security issues
are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

These packages provide the OpenJDK 6 Java Runtime Environment and the
OpenJDK 6 Software Development Kit.

Multiple improper permission check issues were discovered in the AWT,
CORBA, JMX, and Libraries components in OpenJDK. An untrusted Java
application or applet could use these flaws to bypass Java sandbox
restrictions. (CVE-2013-0442, CVE-2013-0445, CVE-2013-0441,
CVE-2013-1475, CVE-2013-1476, CVE-2013-0429, CVE-2013-0450,
CVE-2013-0425, CVE-2013-0426, CVE-2013-0428)

Multiple flaws were found in the way image parsers in the 2D and AWT
components handled image raster parameters. A specially crafted image
could cause Java Virtual Machine memory corruption and, possibly, lead
to arbitrary code execution with the virtual machine privileges.
(CVE-2013-1478, CVE-2013-1480)

A flaw was found in the AWT component's clipboard handling code. An
untrusted Java application or applet could use this flaw to access
clipboard data, bypassing Java sandbox restrictions. (CVE-2013-0432)

The default Java security properties configuration did not restrict
access to certain com.sun.xml.internal packages. An untrusted Java
application or applet could use this flaw to access information,
bypassing certain Java sandbox restrictions. This update lists the
whole package as restricted. (CVE-2013-0435)

Multiple improper permission check issues were discovered in the
Libraries, Networking, and JAXP components. An untrusted Java
application or applet could use these flaws to bypass certain Java
sandbox restrictions. (CVE-2013-0427, CVE-2013-0433, CVE-2013-0434)

It was discovered that the RMI component's CGIHandler class used user
inputs in error messages without any sanitization. An attacker could
use this flaw to perform a cross-site scripting (XSS) attack.
(CVE-2013-0424)

It was discovered that the SSL/TLS implementation in the JSSE
component did not properly enforce handshake message ordering,
allowing an unlimited number of handshake restarts. A remote attacker
could use this flaw to make an SSL/TLS server using JSSE consume an
excessive amount of CPU by continuously restarting the handshake.
(CVE-2013-0440)

It was discovered that the JSSE component did not properly validate
Diffie-Hellman public keys. An SSL/TLS client could possibly use this
flaw to perform a small subgroup attack. (CVE-2013-0443)

This erratum also upgrades the OpenJDK package to IcedTea6 1.11.6.
Refer to the NEWS file, linked to in the References, for further
information.

All users of java-1.6.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-February/003250.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/09");
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
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-1.6.0.0-1.33.1.11.6.0.1.el5_9")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.33.1.11.6.0.1.el5_9")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.33.1.11.6.0.1.el5_9")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.33.1.11.6.0.1.el5_9")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-src-1.6.0.0-1.33.1.11.6.0.1.el5_9")) flag++;


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
