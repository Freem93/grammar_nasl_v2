#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:0068 and 
# Oracle Linux Security Advisory ELSA-2015-0068 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(80900);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/07 20:57:51 $");

  script_cve_id("CVE-2014-3566", "CVE-2014-6585", "CVE-2014-6587", "CVE-2014-6591", "CVE-2014-6593", "CVE-2014-6601", "CVE-2015-0383", "CVE-2015-0395", "CVE-2015-0407", "CVE-2015-0408", "CVE-2015-0410", "CVE-2015-0412");
  script_bugtraq_id(70574, 72132, 72136, 72140, 72142, 72155, 72162, 72165, 72168, 72169, 72173, 72175);
  script_osvdb_id(113251, 117224, 117225, 117227, 117228, 117232, 117233, 117235, 117236, 117237, 117238, 117241);
  script_xref(name:"RHSA", value:"2015:0068");

  script_name(english:"Oracle Linux 5 : java-1.7.0-openjdk (ELSA-2015-0068) (POODLE)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:0068 :

Updated java-1.7.0-openjdk packages that fix multiple security issues
are now available for Red Hat Enterprise Linux 5.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The java-1.7.0-openjdk packages provide the OpenJDK 7 Java Runtime
Environment and the OpenJDK 7 Java Software Development Kit.

A flaw was found in the way the Hotspot component in OpenJDK verified
bytecode from the class files. An untrusted Java application or applet
could possibly use this flaw to bypass Java sandbox restrictions.
(CVE-2014-6601)

Multiple improper permission check issues were discovered in the
JAX-WS, and RMI components in OpenJDK. An untrusted Java application
or applet could use these flaws to bypass Java sandbox restrictions.
(CVE-2015-0412, CVE-2015-0408)

A flaw was found in the way the Hotspot garbage collector handled
phantom references. An untrusted Java application or applet could use
this flaw to corrupt the Java Virtual Machine memory and, possibly,
execute arbitrary code, bypassing Java sandbox restrictions.
(CVE-2015-0395)

A flaw was found in the way the DER (Distinguished Encoding Rules)
decoder in the Security component in OpenJDK handled negative length
values. A specially crafted, DER-encoded input could cause a Java
application to enter an infinite loop when decoded. (CVE-2015-0410)

A flaw was found in the way the SSL 3.0 protocol handled padding bytes
when decrypting messages that were encrypted using block ciphers in
cipher block chaining (CBC) mode. This flaw could possibly allow a
man-in-the-middle (MITM) attacker to decrypt portions of the cipher
text using a padding oracle attack. (CVE-2014-3566)

Note: This update disables SSL 3.0 by default to address this issue.
The jdk.tls.disabledAlgorithms security property can be used to
re-enable SSL 3.0 support if needed. For additional information, refer
to the Red Hat Bugzilla bug linked to in the References section.

It was discovered that the SSL/TLS implementation in the JSSE
component in OpenJDK failed to properly check whether the
ChangeCipherSpec was received during the SSL/TLS connection handshake.
An MITM attacker could possibly use this flaw to force a connection to
be established without encryption being enabled. (CVE-2014-6593)

An information leak flaw was found in the Swing component in OpenJDK.
An untrusted Java application or applet could use this flaw to bypass
certain Java sandbox restrictions. (CVE-2015-0407)

A NULL pointer dereference flaw was found in the MulticastSocket
implementation in the Libraries component of OpenJDK. An untrusted
Java application or applet could possibly use this flaw to bypass
certain Java sandbox restrictions. (CVE-2014-6587)

Multiple boundary check flaws were found in the font parsing code in
the 2D component in OpenJDK. A specially crafted font file could allow
an untrusted Java application or applet to disclose portions of the
Java Virtual Machine memory. (CVE-2014-6585, CVE-2014-6591)

Multiple insecure temporary file use issues were found in the way the
Hotspot component in OpenJDK created performance statistics and error
log files. A local attacker could possibly make a victim using OpenJDK
overwrite arbitrary files using a symlink attack. (CVE-2015-0383)

The CVE-2015-0383 issue was discovered by Red Hat.

All users of java-1.7.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-January/004799.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.7.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/21");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL5", reference:"java-1.7.0-openjdk-1.7.0.75-2.5.4.0.0.1.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.7.0-openjdk-demo-1.7.0.75-2.5.4.0.0.1.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.7.0-openjdk-devel-1.7.0.75-2.5.4.0.0.1.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.7.0-openjdk-javadoc-1.7.0.75-2.5.4.0.0.1.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.7.0-openjdk-src-1.7.0.75-2.5.4.0.0.1.el5_11")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-openjdk / java-1.7.0-openjdk-demo / etc");
}
