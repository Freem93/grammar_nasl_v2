#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(84226);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/10/19 14:25:12 $");

  script_cve_id("CVE-2014-8176", "CVE-2015-1789", "CVE-2015-1790", "CVE-2015-1791", "CVE-2015-1792", "CVE-2015-3216");

  script_name(english:"Scientific Linux Security Update : openssl on SL6.x, SL7.x i386/x86_64");
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
"An invalid free flaw was found in the way OpenSSL handled certain DTLS
handshake messages. A malicious DTLS client or server could cause a
DTLS server or client using OpenSSL to crash or, potentially, execute
arbitrary code. (CVE-2014-8176)

A flaw was found in the way the OpenSSL packages shipped with
Scientific Linux 6 and 7 performed locking in the ssleay_rand_bytes()
function. This issue could possibly cause a multi-threaded application
using OpenSSL to perform an out-of-bounds read and crash.
(CVE-2015-3216)

An out-of-bounds read flaw was found in the X509_cmp_time() function
of OpenSSL. A specially crafted X.509 certificate or a Certificate
Revocation List (CRL) could possibly cause a TLS/SSL server or client
using OpenSSL to crash. (CVE-2015-1789)

A race condition was found in the session handling code of OpenSSL.
This issue could possibly cause a multi-threaded TLS/SSL client using
OpenSSL to double free session ticket data and crash. (CVE-2015-1791)

A flaw was found in the way OpenSSL handled Cryptographic Message
Syntax (CMS) messages. A CMS message with an unknown hash function
identifier could cause an application using OpenSSL to enter an
infinite loop. (CVE-2015-1792)

A NULL pointer dereference was found in the way OpenSSL handled
certain PKCS#7 inputs. A specially crafted PKCS#7 input with missing
EncryptedContent data could cause an application using OpenSSL to
crash. (CVE-2015-1790)

For the update to take effect, all services linked to the OpenSSL
library must be restarted, or the system rebooted."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1506&L=scientific-linux-errata&F=&S=&P=6990
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dbc14ef0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"openssl-1.0.1e-30.el6_6.11")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-debuginfo-1.0.1e-30.el6_6.11")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-devel-1.0.1e-30.el6_6.11")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-perl-1.0.1e-30.el6_6.11")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-static-1.0.1e-30.el6_6.11")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-1.0.1e-42.el7_1.8")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-debuginfo-1.0.1e-42.el7_1.8")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-devel-1.0.1e-42.el7_1.8")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-libs-1.0.1e-42.el7_1.8")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-perl-1.0.1e-42.el7_1.8")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-static-1.0.1e-42.el7_1.8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
