#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:0716 and 
# Oracle Linux Security Advisory ELSA-2015-0716 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(82016);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/07 20:57:51 $");

  script_cve_id("CVE-2015-0209", "CVE-2015-0286", "CVE-2015-0287", "CVE-2015-0288", "CVE-2015-0289", "CVE-2015-0292", "CVE-2015-0293", "CVE-2016-0703", "CVE-2016-0704");
  script_osvdb_id(118817, 119328, 119743, 119755, 119756, 119757, 119761);
  script_xref(name:"RHSA", value:"2015:0716");

  script_name(english:"Oracle Linux 7 : openssl (ELSA-2015-0716)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:0716 :

Updated openssl packages that fix several security issues and one bug
are now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL
v2/v3) and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

An invalid pointer use flaw was found in OpenSSL's ASN1_TYPE_cmp()
function. A remote attacker could crash a TLS/SSL client or server
using OpenSSL via a specially crafted X.509 certificate when the
attacker-supplied certificate was verified by the application.
(CVE-2015-0286)

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

A use-after-free flaw was found in the way OpenSSL imported malformed
Elliptic Curve private keys. A specially crafted key file could cause
an application using OpenSSL to crash when imported. (CVE-2015-0209)

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
CVE-2015-0286, CVE-2015-0287, CVE-2015-0288, CVE-2015-0289,
CVE-2015-0292, and CVE-2015-0293. Upstream acknowledges Stephen Henson
of the OpenSSL development team as the original reporter of
CVE-2015-0286, Emilia Kasper of the OpenSSL development team as the
original reporter of CVE-2015-0287, Brian Carpenter as the original
reporter of CVE-2015-0288, Michal Zalewski of Google as the original
reporter of CVE-2015-0289, Robert Dugal and David Ramos as the
original reporters of CVE-2015-0292, and Sean Burford of Google and
Emilia Kasper of the OpenSSL development team as the original
reporters of CVE-2015-0293.

This update also fixes the following bug :

* When a wrapped Advanced Encryption Standard (AES) key did not
require any padding, it was incorrectly padded with 8 bytes, which
could lead to data corruption and interoperability problems. With this
update, the rounding algorithm in the RFC 5649 key wrapping
implementation has been fixed. As a result, the wrapped key conforms
to the specification, which prevents the described problems.
(BZ#1197667)

All openssl users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. For the
update to take effect, all services linked to the OpenSSL library must
be restarted, or the system rebooted."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-March/004921.html"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/24");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssl-1.0.1e-42.el7_1.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssl-devel-1.0.1e-42.el7_1.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssl-libs-1.0.1e-42.el7_1.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssl-perl-1.0.1e-42.el7_1.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssl-static-1.0.1e-42.el7_1.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-devel / openssl-libs / openssl-perl / etc");
}
