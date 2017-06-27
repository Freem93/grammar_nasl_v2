#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:063. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(82316);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/05 13:44:22 $");

  script_cve_id("CVE-2015-0204", "CVE-2015-0209", "CVE-2015-0286", "CVE-2015-0287", "CVE-2015-0288", "CVE-2015-0289", "CVE-2015-0293");
  script_bugtraq_id(71936, 73225, 73227, 73231, 73232, 73237, 73239);
  script_xref(name:"MDVSA", value:"2015:063");

  script_name(english:"Mandriva Linux Security Advisory : openssl (MDVSA-2015:063)");
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

The ssl3_get_key_exchange function in s3_clnt.c in OpenSSL before
0.9.8zd, 1.0.0 before 1.0.0p, and 1.0.1 before 1.0.1k allows remote
SSL servers to conduct RSA-to-EXPORT_RSA downgrade attacks and
facilitate brute-force decryption by offering a weak ephemeral RSA key
in a noncompliant role, related to the FREAK issue. NOTE: the scope of
this CVE is only client code based on OpenSSL, not EXPORT_RSA issues
associated with servers or other TLS implementations (CVE-2015-0204).

Use-after-free vulnerability in the d2i_ECPrivateKey function in
crypto/ec/ec_asn1.c in OpenSSL before 0.9.8zf, 1.0.0 before 1.0.0r,
1.0.1 before 1.0.1m, and 1.0.2 before 1.0.2a might allow remote
attackers to cause a denial of service (memory corruption and
application crash) or possibly have unspecified other impact via a
malformed Elliptic Curve (EC) private-key file that is improperly
handled during import (CVE-2015-0209).

The ASN1_TYPE_cmp function in crypto/asn1/a_type.c in OpenSSL before
0.9.8zf, 1.0.0 before 1.0.0r, 1.0.1 before 1.0.1m, and 1.0.2 before
1.0.2a does not properly perform boolean-type comparisons, which
allows remote attackers to cause a denial of service (invalid read
operation and application crash) via a crafted X.509 certificate to an
endpoint that uses the certificate-verification feature
(CVE-2015-0286).

The ASN1_item_ex_d2i function in crypto/asn1/tasn_dec.c in OpenSSL
before 0.9.8zf, 1.0.0 before 1.0.0r, 1.0.1 before 1.0.1m, and 1.0.2
before 1.0.2a does not reinitialize CHOICE and ADB data structures,
which might allow attackers to cause a denial of service (invalid
write operation and memory corruption) by leveraging an application
that relies on ASN.1 structure reuse (CVE-2015-0287).

The X509_to_X509_REQ function in crypto/x509/x509_req.c in OpenSSL
before 0.9.8zf, 1.0.0 before 1.0.0r, 1.0.1 before 1.0.1m, and 1.0.2
before 1.0.2a might allow attackers to cause a denial of service (NULL
pointer dereference and application crash) via an invalid certificate
key (CVE-2015-0288).

The PKCS#7 implementation in OpenSSL before 0.9.8zf, 1.0.0 before
1.0.0r, 1.0.1 before 1.0.1m, and 1.0.2 before 1.0.2a does not properly
handle a lack of outer ContentInfo, which allows attackers to cause a
denial of service (NULL pointer dereference and application crash) by
leveraging an application that processes arbitrary PKCS#7 data and
providing malformed data with ASN.1 encoding, related to
crypto/pkcs7/pk7_doit.c and crypto/pkcs7/pk7_lib.c (CVE-2015-0289).

The SSLv2 implementation in OpenSSL before 0.9.8zf, 1.0.0 before
1.0.0r, 1.0.1 before 1.0.1m, and 1.0.2 before 1.0.2a allows remote
attackers to cause a denial of service (s2_lib.c assertion failure and
daemon exit) via a crafted CLIENT-MASTER-KEY message (CVE-2015-0293).

The updated packages have been upgraded to the 1.0.0r version where
these security flaws has been fixed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://openssl.org/news/secadv_20150319.txt"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/30");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64openssl-devel-1.0.0r-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64openssl-engines1.0.0-1.0.0r-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64openssl-static-devel-1.0.0r-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64openssl1.0.0-1.0.0r-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"openssl-1.0.0r-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
