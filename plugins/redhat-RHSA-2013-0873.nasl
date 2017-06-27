#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0873. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66662);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/01/05 16:29:43 $");

  script_cve_id("CVE-2012-5575");
  script_bugtraq_id(60043);
  script_xref(name:"RHSA", value:"2013:0873");

  script_name(english:"RHEL 4 / 5 / 6 : JBoss EAP (RHSA-2013:0873)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated packages for JBoss Enterprise Application Platform 5.2.0 which
fix one security issue are now available for Red Hat Enterprise Linux
4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

JBoss Enterprise Application Platform is a platform for Java
applications, which integrates the JBoss Application Server with JBoss
Hibernate and JBoss Seam.

XML encryption backwards compatibility attacks were found against
various frameworks, including Apache CXF. An attacker could force a
server to use insecure, legacy cryptosystems, even when secure
cryptosystems were enabled on endpoints. By forcing the use of legacy
cryptosystems, flaws such as CVE-2011-1096 and CVE-2011-2487 would be
exposed, allowing plain text to be recovered from cryptograms and
symmetric keys. This issue affected both the JBoss Web Services CXF
(jbossws-cxf) and JBoss Web Services Native (jbossws-native) stacks.
(CVE-2012-5575)

Red Hat would like to thank Tibor Jager, Kenneth G. Paterson and Juraj
Somorovsky of Ruhr-University Bochum for reporting this issue.

If you are using jbossws-cxf, then automatic checks to prevent this
flaw are only run when WS-SecurityPolicy is used to enforce security
requirements. It is best practice to use WS-SecurityPolicy to enforce
security requirements.

If you are using jbossws-native, the fix for this flaw is implemented
by two new configuration parameters in the 'encryption' element. This
element can be a child of 'requires' in both client and server wsse
configuration descriptors (set on a per-application basis via the
application's jboss-wsse-server.xml and jboss-wsse-client.xml files).
The new attributes are 'algorithms' and 'keyWrapAlgorithms'. These
attributes should contain a blank space or comma separated list of
algorithm IDs that are allowed for the encrypted incoming message,
both for encryption and private key wrapping. For backwards
compatibility, no algorithm checks are performed by default for empty
lists or missing attributes.

For example (do not include the line break in your configuration) :

encryption algorithms='aes-192-gcm aes-256-gcm'
keyWrapAlgorithms='rsa_oaep'

Specifies that incoming messages are required to be encrypted, and
that the only permitted encryption algorithms are AES-192 and 256 in
GCM mode, and RSA-OAEP only for key wrapping.

Before performing any decryption, the jbossws-native stack will verify
that each algorithm specified in the incoming messages is included in
the allowed algorithms lists from these new encryption element
attributes. The algorithm values to be used for 'algorithms' and
'keyWrapAlgorithms' are the same as for 'algorithm' and
'keyWrapAlgorithm' in the 'encrypt' element.

Warning: Before applying this update, back up your existing JBoss
Enterprise Application Platform installation (including all
applications and configuration files).

All users of JBoss Enterprise Application Platform 5.2.0 on Red Hat
Enterprise Linux 4, 5, and 6 are advised to upgrade to these updated
packages. The JBoss server process must be restarted for the update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5575.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://ws.apache.org/wss4j/best_practice.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cxf.apache.org/cve-2012-5575.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0873.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache-cxf, jbossws and / or wss4j packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wss4j");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4|5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0873";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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

  if (! (rpm_exists(release:"RHEL4", rpm:"jbossws-") || rpm_exists(release:"RHEL5", rpm:"jbossws-") || rpm_exists(release:"RHEL6", rpm:"jbossws-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL4", reference:"apache-cxf-2.2.12-12.patch_07.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossws-3.1.2-14.SP15_patch_02.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"wss4j-1.5.12-6_patch_03.ep5.el4")) flag++;

  if (rpm_check(release:"RHEL5", reference:"apache-cxf-2.2.12-12.patch_07.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossws-3.1.2-14.SP15_patch_02.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"wss4j-1.5.12-6_patch_03.ep5.el5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"apache-cxf-2.2.12-12.patch_07.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossws-3.1.2-14.SP15_patch_02.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"wss4j-1.5.12-6_patch_03.ep5.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache-cxf / jbossws / wss4j");
  }
}
