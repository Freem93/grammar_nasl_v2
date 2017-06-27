#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0511. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64760);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/05 16:17:31 $");

  script_cve_id("CVE-2012-4543");
  script_bugtraq_id(56843);
  script_osvdb_id(88275, 88276);
  script_xref(name:"RHSA", value:"2013:0511");

  script_name(english:"RHEL 6 : pki-core (RHSA-2013:0511)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pki-core packages that fix multiple security issues, two bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Red Hat Certificate System is an enterprise software system designed
to manage enterprise public key infrastructure (PKI) deployments. PKI
Core contains fundamental packages required by Red Hat Certificate
System, which comprise the Certificate Authority (CA) subsystem.

Note: The Certificate Authority component provided by this advisory
cannot be used as a standalone server. It is installed and operates as
a part of Identity Management (the IPA component) in Red Hat
Enterprise Linux.

Multiple cross-site scripting flaws were discovered in Certificate
System. An attacker could use these flaws to perform a cross-site
scripting (XSS) attack against victims using Certificate System's web
interface. (CVE-2012-4543)

This update also fixes the following bugs :

* Previously, due to incorrect conversion of large integers while
generating a new serial number, some of the most significant bits in
the serial number were truncated. Consequently, the serial number
generated for certificates was sometimes smaller than expected and
this incorrect conversion in turn led to a collision if a certificate
with the smaller number already existed in the database. This update
removes the incorrect integer conversion so that no serial numbers are
truncated. As a result, the installation wizard proceeds as expected.
(BZ#841663)

* The certificate authority used a different profile for issuing the
audit certificate than it used for renewing it. The issuing profile
was for two years, and the renewal was for six months. They should
both be for two years. This update sets the default and constraint
parameters in the caSignedLogCert.cfg audit certificate renewal
profile to two years. (BZ#844459)

This update also adds the following enhancements :

* IPA (Identity, Policy and Audit) now provides an improved way to
determine that PKI is up and ready to service requests. Checking the
service status was not sufficient. This update creates a mechanism for
clients to determine that the PKI subsystem is up using the
getStatus() function to query the cs.startup_state in CS.cfg.
(BZ#858864)

* This update increases the default root CA validity period from eight
years to twenty years. (BZ#891985)

All users of pki-core are advised to upgrade to these updated
packages, which fix these issues and add these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4543.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0511.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-common-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-java-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-java-tools-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-native-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-silent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-symkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-util-javadoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/21");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0511";
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
  if (rpm_check(release:"RHEL6", reference:"pki-ca-9.0.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pki-common-9.0.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pki-common-javadoc-9.0.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pki-core-debuginfo-9.0.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pki-core-debuginfo-9.0.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pki-java-tools-9.0.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pki-java-tools-javadoc-9.0.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pki-native-tools-9.0.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pki-native-tools-9.0.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pki-selinux-9.0.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pki-setup-9.0.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pki-silent-9.0.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pki-symkey-9.0.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pki-symkey-9.0.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pki-util-9.0.3-30.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pki-util-javadoc-9.0.3-30.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pki-ca / pki-common / pki-common-javadoc / pki-core-debuginfo / etc");
  }
}
