#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1620 and 
# CentOS Errata and Security Advisory 2014:1620 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(78486);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/09/18 13:38:20 $");

  script_cve_id("CVE-2014-6457", "CVE-2014-6502", "CVE-2014-6504", "CVE-2014-6506", "CVE-2014-6511", "CVE-2014-6512", "CVE-2014-6517", "CVE-2014-6519", "CVE-2014-6531", "CVE-2014-6558");
  script_osvdb_id(99712, 113325, 113326, 113329, 113330, 113331, 113332, 113333, 113336, 113337);
  script_xref(name:"RHSA", value:"2014:1620");

  script_name(english:"CentOS 6 / 7 : java-1.7.0-openjdk (CESA-2014:1620)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.7.0-openjdk packages that fix multiple security issues
and one bug are now available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The java-1.7.0-openjdk packages provide the OpenJDK 7 Java Runtime
Environment and the OpenJDK 7 Java Software Development Kit.

Multiple flaws were discovered in the Libraries, 2D, and Hotspot
components in OpenJDK. An untrusted Java application or applet could
use these flaws to bypass certain Java sandbox restrictions.
(CVE-2014-6506, CVE-2014-6531, CVE-2014-6502, CVE-2014-6511,
CVE-2014-6504, CVE-2014-6519)

It was discovered that the StAX XML parser in the JAXP component in
OpenJDK performed expansion of external parameter entities even when
external entity substitution was disabled. A remote attacker could use
this flaw to perform XML eXternal Entity (XXE) attack against
applications using the StAX parser to parse untrusted XML documents.
(CVE-2014-6517)

It was discovered that the DatagramSocket implementation in OpenJDK
failed to perform source address checks for packets received on a
connected socket. A remote attacker could use this flaw to have their
packets processed as if they were received from the expected source.
(CVE-2014-6512)

It was discovered that the TLS/SSL implementation in the JSSE
component in OpenJDK failed to properly verify the server identity
during the renegotiation following session resumption, making it
possible for malicious TLS/SSL servers to perform a Triple Handshake
attack against clients using JSSE and client certificate
authentication. (CVE-2014-6457)

It was discovered that the CipherInputStream class implementation in
OpenJDK did not properly handle certain exceptions. This could
possibly allow an attacker to affect the integrity of an encrypted
stream handled by this class. (CVE-2014-6558)

The CVE-2014-6512 was discovered by Florian Weimer of Red Hat Product
Security.

Note: If the web browser plug-in provided by the icedtea-web package
was installed, the issues exposed via Java applets could have been
exploited without user interaction if a user visited a malicious
website.

This update also fixes the following bug :

* The TLS/SSL implementation in OpenJDK previously failed to handle
Diffie-Hellman (DH) keys with more than 1024 bits. This caused client
applications using JSSE to fail to establish TLS/SSL connections to
servers using larger DH keys during the connection handshake. This
update adds support for DH keys with size up to 2048 bits.
(BZ#1148309)

All users of java-1.7.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-October/020690.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?083ec666"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2014-October/001470.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f18a19d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.7.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-1.7.0.71-2.5.3.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-demo-1.7.0.71-2.5.3.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-devel-1.7.0.71-2.5.3.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-javadoc-1.7.0.71-2.5.3.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-src-1.7.0.71-2.5.3.1.el6")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.7.0-openjdk-1.7.0.71-2.5.3.1.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.7.0-openjdk-accessibility-1.7.0.71-2.5.3.1.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.7.0-openjdk-demo-1.7.0.71-2.5.3.1.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.7.0-openjdk-devel-1.7.0.71-2.5.3.1.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.7.0-openjdk-headless-1.7.0.71-2.5.3.1.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.7.0-openjdk-javadoc-1.7.0.71-2.5.3.1.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.7.0-openjdk-src-1.7.0.71-2.5.3.1.el7_0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
