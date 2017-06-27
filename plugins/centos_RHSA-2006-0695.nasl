#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0695 and 
# CentOS Errata and Security Advisory 2006:0695 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(22484);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2006-2937", "CVE-2006-2940", "CVE-2006-3738", "CVE-2006-4343");
  script_osvdb_id(29260, 29261, 29262, 29263);
  script_xref(name:"RHSA", value:"2006:0695");

  script_name(english:"CentOS 3 / 4 : openssl (CESA-2006:0695)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
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
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013297.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?02a67664"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013298.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d3d1953b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013299.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f6e6007c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013306.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5bad3202"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013307.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?457a544e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl096b");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/02");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"openssl-0.9.7a-33.21")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssl-devel-0.9.7a-33.21")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssl-perl-0.9.7a-33.21")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssl096b-0.9.6b-16.46")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openssl-0.9.7a-43.14")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openssl-0.9.7a-43.14")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openssl-devel-0.9.7a-43.14")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openssl-devel-0.9.7a-43.14")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openssl-perl-0.9.7a-43.14")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openssl-perl-0.9.7a-43.14")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openssl096b-0.9.6b-22.46")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openssl096b-0.9.6b-22.46")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
