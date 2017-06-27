#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61293);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/05/22 11:17:46 $");

  script_cve_id("CVE-2012-0884", "CVE-2012-1165");

  script_name(english:"Scientific Linux Security Update : openssl on SL5.x, SL6.x i386/x86_64");
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
"OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL
v2/v3) and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

A NULL pointer dereference flaw was found in the way OpenSSL parsed
Secure/Multipurpose Internet Mail Extensions (S/MIME) messages. An
attacker could use this flaw to crash an application that uses OpenSSL
to decrypt or verify S/MIME messages. (CVE-2012-1165)

A flaw was found in the PKCS#7 and Cryptographic Message Syntax (CMS)
implementations in OpenSSL. An attacker could possibly use this flaw
to perform a Bleichenbacher attack to decrypt an encrypted CMS,
PKCS#7, or S/MIME message by sending a large number of chosen
ciphertext messages to a service using OpenSSL and measuring error
response times. (CVE-2012-0884)

This update also fixes a regression caused by the fix for
CVE-2011-4619, released in a previous update, which caused Server
Gated Cryptography (SGC) handshakes to fail.

All OpenSSL users should upgrade to these updated packages, which
contain backported patches to resolve these issues. For the update to
take effect, all services linked to the OpenSSL library must be
restarted, or the system rebooted."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1203&L=scientific-linux-errata&T=0&P=4960
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7661ba4f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"openssl-0.9.8e-22.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openssl-debuginfo-0.9.8e-22.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openssl-devel-0.9.8e-22.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openssl-perl-0.9.8e-22.el5_8.1")) flag++;

if (rpm_check(release:"SL6", reference:"openssl-1.0.0-20.el6_2.3")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-debuginfo-1.0.0-20.el6_2.3")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-devel-1.0.0-20.el6_2.3")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-perl-1.0.0-20.el6_2.3")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-static-1.0.0-20.el6_2.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
