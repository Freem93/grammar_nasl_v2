#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(80905);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/22 14:23:02 $");

  script_cve_id("CVE-2014-3570", "CVE-2014-3571", "CVE-2014-3572", "CVE-2014-8275", "CVE-2015-0204", "CVE-2015-0205", "CVE-2015-0206");

  script_name(english:"Scientific Linux Security Update : openssl on SL6.x, SL7.x i386/x86_64 (FREAK)");
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
"A NULL pointer dereference flaw was found in the DTLS implementation
of OpenSSL. A remote attacker could send a specially crafted DTLS
message, which would cause an OpenSSL server to crash. (CVE-2014-3571)

A memory leak flaw was found in the way the dtls1_buffer_record()
function of OpenSSL parsed certain DTLS messages. A remote attacker
could send multiple specially crafted DTLS messages to exhaust all
available memory of a DTLS server. (CVE-2015-0206)

It was found that OpenSSL's BigNumber Squaring implementation could
produce incorrect results under certain special conditions. This flaw
could possibly affect certain OpenSSL library functionality, such as
RSA blinding. Note that this issue occurred rarely and with a low
probability, and there is currently no known way of exploiting it.
(CVE-2014-3570)

It was discovered that OpenSSL would perform an ECDH key exchange with
a non-ephemeral key even when the ephemeral ECDH cipher suite was
selected. A malicious server could make a TLS/SSL client using OpenSSL
use a weaker key exchange method than the one requested by the user.
(CVE-2014-3572)

It was discovered that OpenSSL would accept ephemeral RSA keys when
using non-export RSA cipher suites. A malicious server could make a
TLS/SSL client using OpenSSL use a weaker key exchange method.
(CVE-2015-0204)

Multiple flaws were found in the way OpenSSL parsed X.509
certificates. An attacker could use these flaws to modify an X.509
certificate to produce a certificate with a different fingerprint
without invalidating its signature, and possibly bypass
fingerprint-based blacklisting in applications. (CVE-2014-8275)

It was found that an OpenSSL server would, under certain conditions,
accept Diffie-Hellman client certificates without the use of a private
key. An attacker could use a user's client certificate to authenticate
as that user, without needing the private key. (CVE-2015-0205)

For the update to take effect, all services linked to the OpenSSL
library (such as httpd and other SSL-enabled services) must be
restarted or the system rebooted."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1501&L=scientific-linux-errata&T=0&P=1506
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e3561a1f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/21");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/22");
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
if (rpm_check(release:"SL6", reference:"openssl-1.0.1e-30.el6_6.5")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-debuginfo-1.0.1e-30.el6_6.5")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-devel-1.0.1e-30.el6_6.5")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-perl-1.0.1e-30.el6_6.5")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-static-1.0.1e-30.el6_6.5")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-1.0.1e-34.el7_0.7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-debuginfo-1.0.1e-34.el7_0.7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-devel-1.0.1e-34.el7_0.7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-libs-1.0.1e-34.el7_0.7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-perl-1.0.1e-34.el7_0.7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-static-1.0.1e-34.el7_0.7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
