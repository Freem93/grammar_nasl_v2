#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0800 and 
# CentOS Errata and Security Advisory 2015:0800 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(82783);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/17 21:12:10 $");

  script_cve_id("CVE-2014-8275", "CVE-2015-0204", "CVE-2015-0287", "CVE-2015-0288", "CVE-2015-0289", "CVE-2015-0292", "CVE-2015-0293", "CVE-2016-0703", "CVE-2016-0704");
  script_osvdb_id(116792, 116794, 119328, 119743, 119755, 119756, 119757);
  script_xref(name:"RHSA", value:"2015:0800");

  script_name(english:"CentOS 5 : openssl (CESA-2015:0800) (FREAK)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssl packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL
v2/v3) and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

It was discovered that OpenSSL would accept ephemeral RSA keys when
using non-export RSA cipher suites. A malicious server could make a
TLS/SSL client using OpenSSL use a weaker key exchange method.
(CVE-2015-0204)

An integer underflow flaw, leading to a buffer overflow, was found in
the way OpenSSL decoded malformed Base64-encoded inputs. An attacker
able to make an application using OpenSSL decode a specially crafted
Base64-encoded input (such as a PEM file) could use this flaw to cause
the application to crash. Note: this flaw is not exploitable via the
TLS/SSL protocol because the data being transferred is not
Base64-encoded. (CVE-2015-0292)

A denial of service flaw was found in the way OpenSSL handled SSLv2
handshake messages. A remote attacker could use this flaw to cause a
TLS/SSL server using OpenSSL to exit on a failed assertion if it had
both the SSLv2 protocol and EXPORT-grade cipher suites enabled.
(CVE-2015-0293)

Multiple flaws were found in the way OpenSSL parsed X.509
certificates. An attacker could use these flaws to modify an X.509
certificate to produce a certificate with a different fingerprint
without invalidating its signature, and possibly bypass
fingerprint-based blacklisting in applications. (CVE-2014-8275)

An out-of-bounds write flaw was found in the way OpenSSL reused
certain ASN.1 structures. A remote attacker could possibly use a
specially crafted ASN.1 structure that, when parsed by an application,
would cause that application to crash. (CVE-2015-0287)

A NULL pointer dereference flaw was found in OpenSSL's X.509
certificate handling implementation. A specially crafted X.509
certificate could cause an application using OpenSSL to crash if the
application attempted to convert the certificate to a certificate
request. (CVE-2015-0288)

A NULL pointer dereference was found in the way OpenSSL handled
certain PKCS#7 inputs. An attacker able to make an application using
OpenSSL verify, decrypt, or parse a specially crafted PKCS#7 input
could cause that application to crash. TLS/SSL clients and servers
using OpenSSL were not affected by this flaw. (CVE-2015-0289)

Red Hat would like to thank the OpenSSL project for reporting
CVE-2015-0287, CVE-2015-0288, CVE-2015-0289, CVE-2015-0292, and
CVE-2015-0293. Upstream acknowledges Emilia Kasper of the OpenSSL
development team as the original reporter of CVE-2015-0287, Brian
Carpenter as the original reporter of CVE-2015-0288, Michal Zalewski
of Google as the original reporter of CVE-2015-0289, Robert Dugal and
David Ramos as the original reporters of CVE-2015-0292, and Sean
Burford of Google and Emilia Kasper of the OpenSSL development team
as the original reporters of CVE-2015-0293.

All openssl users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. For the
update to take effect, all services linked to the OpenSSL library must
be restarted, or the system rebooted."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-April/021064.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?44363a11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"openssl-0.9.8e-33.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssl-devel-0.9.8e-33.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssl-perl-0.9.8e-33.el5_11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
