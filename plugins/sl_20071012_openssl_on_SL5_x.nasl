#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60267);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/03/06 11:47:00 $");

  script_cve_id("CVE-2007-3108", "CVE-2007-4995", "CVE-2007-5135");

  script_name(english:"Scientific Linux Security Update : openssl on SL5.x i386/x86_64");
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
"OpenSSL is a toolkit that implements Secure Sockets Layer (SSL v2/v3)
and Transport Layer Security (TLS v1) protocols as well as a
full-strength general purpose cryptography library. Datagram TLS
(DTLS) is a protocol based on TLS that is capable of securing datagram
transport (UDP for instance).

The OpenSSL security team discovered a flaw in DTLS support. An
attacker could create a malicious client or server that could trigger
a heap overflow. This is possibly exploitable to run arbitrary code,
but it has not been verified (CVE-2007-5135). Note that this flaw only
affects applications making use of DTLS. Scientific Linux does not
ship any DTLS client or server applications.

A flaw was found in the SSL_get_shared_ciphers() utility function. An
attacker could send a list of ciphers to an application that used this
function and overrun a buffer with a single byte (CVE-2007-4995). Few
applications make use of this vulnerable function and generally it is
used only when applications are compiled for debugging.

A number of possible side-channel attacks were discovered affecting
OpenSSL. A local attacker could possibly obtain RSA private keys being
used on a system. In practice these attacks would be difficult to
perform outside of a lab environment. This update contains backported
patches designed to mitigate these issues. (CVE-2007-3108).

Users of OpenSSL should upgrade to these updated packages, which
contain backported patches to resolve these issues.

Please note that the fix for the DTLS flaw involved an overhaul of the
DTLS handshake processing which may introduce incompatibilities if a
new client is used with an older server.

After installing this update, users are advised to either restart all
services that use OpenSSL or restart their system."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0710&L=scientific-linux-errata&T=0&P=1222
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?101a9305"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected openssl, openssl-devel and / or openssl-perl
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", cpu:"i386", reference:"openssl-0.9.8b-8.3.el5.2")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"openssl-0.9.8b-8.3.2")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"openssl-devel-0.9.8b-8.3.el5.2")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"openssl-devel-0.9.8b-8.3.2")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"openssl-perl-0.9.8b-8.3.el5.2")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"openssl-perl-0.9.8b-8.3.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
