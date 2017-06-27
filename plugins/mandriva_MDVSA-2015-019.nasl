#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:019. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(80456);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/01 13:42:18 $");

  script_cve_id("CVE-2014-3569", "CVE-2014-3570", "CVE-2014-3571", "CVE-2014-3572", "CVE-2014-8275", "CVE-2015-0204", "CVE-2015-0205", "CVE-2015-0206");
  script_bugtraq_id(71934, 71935, 71936, 71937, 71939, 71940, 71941, 71942);
  script_xref(name:"MDVSA", value:"2015:019");

  script_name(english:"Mandriva Linux Security Advisory : openssl (MDVSA-2015:019)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities has been discovered and corrected in 
openssl :

A carefully crafted DTLS message can cause a segmentation fault in
OpenSSL due to a NULL pointer dereference. This could lead to a Denial
Of Service attack (CVE-2014-3571).

A memory leak can occur in the dtls1_buffer_record function under
certain conditions. In particular this could occur if an attacker sent
repeated DTLS records with the same sequence number but for the next
epoch. The memory leak could be exploited by an attacker in a Denial
of Service attack through memory exhaustion (CVE-2015-0206).

When openssl is built with the no-ssl3 option and a SSL v3 ClientHello
is received the ssl method would be set to NULL which could later
result in a NULL pointer dereference (CVE-2014-3569).

An OpenSSL client will accept a handshake using an ephemeral ECDH
ciphersuite using an ECDSA certificate if the server key exchange
message is omitted. This effectively removes forward secrecy from the
ciphersuite (CVE-2014-3572).

An OpenSSL client will accept the use of an RSA temporary key in a
non-export RSA key exchange ciphersuite. A server could present a weak
temporary key and downgrade the security of the session
(CVE-2015-0204).

An OpenSSL server will accept a DH certificate for client
authentication without the certificate verify message. This
effectively allows a client to authenticate without the use of a
private key. This only affects servers which trust a client
certificate authority which issues certificates containing DH keys:
these are extremely rare and hardly ever encountered (CVE-2015-0205).

OpenSSL accepts several non-DER-variations of certificate signature
algorithm and signature encodings. OpenSSL also does not enforce a
match between the signature algorithm between the signed and unsigned
portions of the certificate. By modifying the contents of the
signature algorithm or the encoding of the signature, it is possible
to change the certificate's fingerprint. This does not allow an
attacker to forge certificates, and does not affect certificate
verification or OpenSSL servers/clients in any other way. It also does
not affect common revocation mechanisms. Only custom applications that
rely on the uniqueness of the fingerprint (e.g. certificate
blacklists) may be affected (CVE-2014-8275).

Bignum squaring (BN_sqr) may produce incorrect results on some
platforms, including x86_64. This bug occurs at random with a very low
probability, and is not known to be exploitable in any way, though its
exact impact is difficult to determine (CVE-2014-3570).

The updated packages have been upgraded to the 1.0.0p version where
these security flaws has been fixed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openssl.org/news/secadv/20150108.txt"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openssl-engines1.0.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openssl-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openssl1.0.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64openssl-devel-1.0.0p-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64openssl-engines1.0.0-1.0.0p-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64openssl-static-devel-1.0.0p-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64openssl1.0.0-1.0.0p-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"openssl-1.0.0p-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
