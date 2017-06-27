#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2006:0695 and 
# Oracle Linux Security Advisory ELSA-2006-0695 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67411);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/07 20:46:55 $");

  script_cve_id("CVE-2006-2937", "CVE-2006-2940", "CVE-2006-3738", "CVE-2006-4343");
  script_osvdb_id(29260, 29261, 29262, 29263);
  script_xref(name:"RHSA", value:"2006:0695");

  script_name(english:"Oracle Linux 3 : openssl (ELSA-2006-0695)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2006:0695 :

Updated OpenSSL packages are now available to correct several security
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
    value:"https://oss.oracle.com/pipermail/el-errata/2007-March/000085.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl096b");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/28");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"openssl-0.9.7a-33.21")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"openssl-0.9.7a-33.21")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"openssl-devel-0.9.7a-33.21")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"openssl-devel-0.9.7a-33.21")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"openssl-perl-0.9.7a-33.21")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"openssl-perl-0.9.7a-33.21")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"openssl096b-0.9.6b-16.46")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"openssl096b-0.9.6b-16.46")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-devel / openssl-perl / openssl096b");
}
