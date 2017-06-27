#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(93795);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/10/19 14:37:26 $");

  script_cve_id("CVE-2016-2177", "CVE-2016-2178", "CVE-2016-2179", "CVE-2016-2180", "CVE-2016-2181", "CVE-2016-2182", "CVE-2016-2183", "CVE-2016-6302", "CVE-2016-6304", "CVE-2016-6306");

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
"Security Fix(es) :

  - A memory leak flaw was found in the way OpenSSL handled
    TLS status request extension data during session
    renegotiation. A remote attacker could cause a TLS
    server using OpenSSL to consume an excessive amount of
    memory and, possibly, exit unexpectedly after exhausting
    all available memory, if it enabled OCSP stapling
    support. (CVE-2016-6304)

  - It was discovered that OpenSSL did not always use
    constant time operations when computing Digital
    Signature Algorithm (DSA) signatures. A local attacker
    could possibly use this flaw to obtain a private DSA key
    belonging to another user or service running on the same
    system. (CVE-2016-2178)

  - It was discovered that the Datagram TLS (DTLS)
    implementation could fail to release memory in certain
    cases. A malicious DTLS client could cause a DTLS server
    using OpenSSL to consume an excessive amount of memory
    and, possibly, exit unexpectedly after exhausting all
    available memory. (CVE-2016-2179)

  - A flaw was found in the Datagram TLS (DTLS) replay
    protection implementation in OpenSSL. A remote attacker
    could possibly use this flaw to make a DTLS server using
    OpenSSL to reject further packets sent from a DTLS
    client over an established DTLS connection.
    (CVE-2016-2181)

  - An out of bounds write flaw was discovered in the
    OpenSSL BN_bn2dec() function. An attacker able to make
    an application using OpenSSL to process a large BIGNUM
    could cause the application to crash or, possibly,
    execute arbitrary code. (CVE-2016-2182)

  - A flaw was found in the DES/3DES cipher was used as part
    of the TLS/SSL protocol. A man-in-the-middle attacker
    could use this flaw to recover some plaintext data by
    capturing large amounts of encrypted traffic between
    TLS/SSL server and client if the communication used a
    DES/3DES based ciphersuite. (CVE-2016-2183)

This update mitigates the CVE-2016-2183 issue by lowering priority of
DES cipher suites so they are not preferred over cipher suites using
AES. For compatibility reasons, DES cipher suites remain enabled by
default and included in the set of cipher suites identified by the
HIGH cipher string. Future updates may move them to MEDIUM or not
enable them by default.

  - An integer underflow flaw leading to a buffer over-read
    was found in the way OpenSSL parsed TLS session tickets.
    A remote attacker could use this flaw to crash a TLS
    server using OpenSSL if it used SHA-512 as HMAC for
    session tickets. (CVE-2016-6302)

  - Multiple integer overflow flaws were found in the way
    OpenSSL performed pointer arithmetic. A remote attacker
    could possibly use these flaws to cause a TLS/SSL server
    or client using OpenSSL to crash. (CVE-2016-2177)

  - An out of bounds read flaw was found in the way OpenSSL
    formatted Public Key Infrastructure Time-Stamp Protocol
    data for printing. An attacker could possibly cause an
    application using OpenSSL to crash if it printed time
    stamp data from the attacker. (CVE-2016-2180)

  - Multiple out of bounds read flaws were found in the way
    OpenSSL handled certain TLS/SSL protocol handshake
    messages. A remote attacker could possibly use these
    flaws to crash a TLS/SSL server or client using OpenSSL.
    (CVE-2016-6306)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1609&L=scientific-linux-errata&F=&S=&P=9018
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7dfe070f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"openssl-1.0.1e-48.sl6_8.3")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-debuginfo-1.0.1e-48.sl6_8.3")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-devel-1.0.1e-48.sl6_8.3")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-perl-1.0.1e-48.sl6_8.3")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-static-1.0.1e-48.sl6_8.3")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-1.0.1e-51.el7_2.7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-debuginfo-1.0.1e-51.el7_2.7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-devel-1.0.1e-51.el7_2.7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-libs-1.0.1e-51.el7_2.7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-perl-1.0.1e-51.el7_2.7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssl-static-1.0.1e-51.el7_2.7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
