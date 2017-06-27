#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(82760);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/22 14:23:02 $");

  script_cve_id("CVE-2014-8275", "CVE-2015-0204", "CVE-2015-0287", "CVE-2015-0288", "CVE-2015-0289", "CVE-2015-0292", "CVE-2015-0293");

  script_name(english:"Scientific Linux Security Update : openssl on SL5.x i386/x86_64 (FREAK)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that OpenSSL would accept ephemeral RSA keys when
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

For the update to take effect, all services linked to the OpenSSL
library must be restarted, or the system rebooted."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1504&L=scientific-linux-errata&T=0&P=847
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?39449cea"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/13");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"openssl-0.9.8e-33.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"openssl-debuginfo-0.9.8e-33.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"openssl-devel-0.9.8e-33.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"openssl-perl-0.9.8e-33.el5_11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
