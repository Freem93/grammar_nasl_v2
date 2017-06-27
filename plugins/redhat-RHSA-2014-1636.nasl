#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1636. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78459);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/06 15:50:59 $");

  script_cve_id("CVE-2014-6457", "CVE-2014-6468", "CVE-2014-6502", "CVE-2014-6504", "CVE-2014-6506", "CVE-2014-6511", "CVE-2014-6512", "CVE-2014-6517", "CVE-2014-6519", "CVE-2014-6531", "CVE-2014-6558", "CVE-2014-6562");
  script_bugtraq_id(70488, 70523, 70533, 70538, 70544, 70548, 70552, 70556, 70564, 70567, 70570, 70572);
  script_osvdb_id(99712, 113317, 113324, 113325, 113326, 113329, 113330, 113331, 113332, 113333, 113336, 113337);
  script_xref(name:"RHSA", value:"2014:1636");

  script_name(english:"RHEL 6 : java-1.8.0-openjdk (RHSA-2014:1636)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.8.0-openjdk packages that fix multiple security issues
are now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The java-1.8.0-openjdk packages provide the OpenJDK 8 Java Runtime
Environment and the OpenJDK 8 Java Software Development Kit.

It was discovered that the Libraries component in OpenJDK failed to
properly handle ZIP archives that contain entries with a NUL byte used
in the file names. An untrusted Java application or applet could use
this flaw to bypass Java sandbox restrictions. (CVE-2014-6562)

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

It was discovered that the Hotspot component in OpenJDK failed to
properly handle malformed Shared Archive files. A local attacker able
to modify a Shared Archive file used by a virtual machine of a
different user could possibly use this flaw to escalate their
privileges. (CVE-2014-6468)

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

All users of java-1.8.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6457.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6468.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6502.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6504.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6506.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6511.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6512.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6517.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6519.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6531.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6558.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6562.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-1636.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:1636";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-openjdk-1.8.0.25-1.b17.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-openjdk-1.8.0.25-1.b17.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.25-1.b17.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.25-1.b17.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-openjdk-demo-1.8.0.25-1.b17.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-1.8.0.25-1.b17.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-openjdk-devel-1.8.0.25-1.b17.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-1.8.0.25-1.b17.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-openjdk-headless-1.8.0.25-1.b17.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-1.8.0.25-1.b17.el6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"java-1.8.0-openjdk-javadoc-1.8.0.25-1.b17.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-openjdk-src-1.8.0.25-1.b17.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-1.8.0.25-1.b17.el6")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk / java-1.8.0-openjdk-debuginfo / etc");
  }
}
