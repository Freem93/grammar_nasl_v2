#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61043);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:55 $");

  script_cve_id("CVE-2011-0014");

  script_name(english:"Scientific Linux Security Update : openssl on SL6.x i386/x86_64");
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

A buffer over-read flaw was discovered in the way OpenSSL parsed the
Certificate Status Request TLS extensions in ClientHello TLS handshake
messages. A remote attacker could possibly use this flaw to crash an
SSL server using the affected OpenSSL functionality. (CVE-2011-0014)

This update fixes the following bugs :

  - The 'openssl speed' command (which provides algorithm
    speed measurement) failed when openssl was running in
    FIPS (Federal Information Processing Standards) mode,
    even if testing of FIPS approved algorithms was
    requested. FIPS mode disables ciphers and cryptographic
    hash algorithms that are not approved by the NIST
    (National Institute of Standards and Technology)
    standards. With this update, the 'openssl speed' command
    no longer fails. (BZ#619762)

  - The 'openssl pkcs12 -export' command failed to export a
    PKCS#12 file in FIPS mode. The default algorithm for
    encrypting a certificate in the PKCS#12 file was not
    FIPS approved and thus did not work. The command now
    uses a FIPS approved algorithm by default in FIPS mode.
    (BZ#673453)

This update also adds the following enhancements :

  - The 'openssl s_server' command, which previously
    accepted connections only over IPv4, now accepts
    connections over IPv6. (BZ#601612)

  - For the purpose of allowing certain maintenance commands
    to be run (such as 'rsync'), an
    'OPENSSL_FIPS_NON_APPROVED_MD5_ALLOW' environment
    variable has been added. When a system is configured for
    FIPS mode and is in a maintenance state, this newly
    added environment variable can be set to allow software
    that requires the use of an MD5 cryptographic hash
    algorithm to be run, even though the hash algorithm is
    not approved by the FIPS-140-2 standard. (BZ#673071)

Users of OpenSSL are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues and add these
enhancements. For the update to take effect, all services linked to
the OpenSSL library must be restarted, or the system rebooted."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1106&L=scientific-linux-errata&T=0&P=302
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?749187f9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=601612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=619762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=673071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=673453"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"openssl-1.0.0-10.el6")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-debuginfo-1.0.0-10.el6")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-devel-1.0.0-10.el6")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-perl-1.0.0-10.el6")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-static-1.0.0-10.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
