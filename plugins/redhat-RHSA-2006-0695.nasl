#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0695. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22472);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/29 15:35:20 $");

  script_cve_id("CVE-2006-2937", "CVE-2006-2940", "CVE-2006-3738", "CVE-2006-4343");
  script_osvdb_id(29260, 29261, 29262, 29263);
  script_xref(name:"RHSA", value:"2006:0695");

  script_name(english:"RHEL 2.1 / 3 / 4 : openssl (RHSA-2006:0695)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated OpenSSL packages are now available to correct several security
issues.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The OpenSSL toolkit provides support for secure communications between
machines. OpenSSL includes a certificate management tool and shared
libraries which provide various cryptographic algorithms and
protocols.

Tavis Ormandy and Will Drewry of the Google Security Team discovered a
buffer overflow in the SSL_get_shared_ciphers() utility function. An
attacker could send a list of ciphers to an application that used this
function and overrun a buffer (CVE-2006-3738). Few applications make
use of this vulnerable function and generally it is used only when
applications are compiled for debugging.

Tavis Ormandy and Will Drewry of the Google Security Team discovered a
flaw in the SSLv2 client code. When a client application used OpenSSL
to create an SSLv2 connection to a malicious server, that server could
cause the client to crash. (CVE-2006-4343)

Dr S. N. Henson of the OpenSSL core team and Open Network Security
recently developed an ASN.1 test suite for NISCC (www.niscc.gov.uk)
which uncovered denial of service vulnerabilities :

* Certain public key types can take disproportionate amounts of time
to process, leading to a denial of service. (CVE-2006-2940)

* During parsing of certain invalid ASN.1 structures an error
condition was mishandled. This can result in an infinite loop which
consumed system memory (CVE-2006-2937). This issue does not affect the
OpenSSL version distributed in Red Hat Enterprise Linux 2.1.

These vulnerabilities can affect applications which use OpenSSL to
parse ASN.1 data from untrusted sources, including SSL servers which
enable client authentication and S/MIME applications.

Users are advised to upgrade to these updated packages, which contain
backported patches to correct these issues.

Note: After installing this update, users are advised to either
restart all services that use OpenSSL or restart their system."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-2937.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-2940.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-3738.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-4343.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openssl.org/news/secadv/20060928.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2006-0695.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl095a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl096");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl096b");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(2\.1|3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x / 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2006:0695";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl-0.9.6b-46")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i686", reference:"openssl-0.9.6b-46")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl-devel-0.9.6b-46")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl-perl-0.9.6b-46")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl095a-0.9.5a-32")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl096-0.9.6-32")) flag++;

  if (rpm_check(release:"RHEL3", reference:"openssl-0.9.7a-33.21")) flag++;
  if (rpm_check(release:"RHEL3", reference:"openssl-devel-0.9.7a-33.21")) flag++;
  if (rpm_check(release:"RHEL3", reference:"openssl-perl-0.9.7a-33.21")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"openssl096b-0.9.6b-16.46")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"s390", reference:"openssl096b-0.9.6b-16.46")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"x86_64", reference:"openssl096b-0.9.6b-16.46")) flag++;

  if (rpm_check(release:"RHEL4", reference:"openssl-0.9.7a-43.14")) flag++;
  if (rpm_check(release:"RHEL4", reference:"openssl-devel-0.9.7a-43.14")) flag++;
  if (rpm_check(release:"RHEL4", reference:"openssl-perl-0.9.7a-43.14")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openssl096b-0.9.6b-22.46")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"s390", reference:"openssl096b-0.9.6b-22.46")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"openssl096b-0.9.6b-22.46")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-devel / openssl-perl / openssl095a / openssl096 / etc");
  }
}
