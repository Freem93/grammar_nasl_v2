#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:310. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(42996);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/28 21:39:23 $");

  script_cve_id("CVE-2009-1377", "CVE-2009-1378", "CVE-2009-1379", "CVE-2009-1386", "CVE-2009-1387", "CVE-2009-2409");
  script_bugtraq_id(35001, 35138, 35174, 35417);
  script_xref(name:"MDVSA", value:"2009:310");

  script_name(english:"Mandriva Linux Security Advisory : openssl (MDVSA-2009:310)");
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
"Multiple security vulnerabilities has been identified and fixed in
OpenSSL :

The dtls1_buffer_record function in ssl/d1_pkt.c in OpenSSL 0.9.8k and
earlier 0.9.8 versions allows remote attackers to cause a denial of
service (memory consumption) via a large series of future epoch DTLS
records that are buffered in a queue, aka DTLS record buffer
limitation bug. (CVE-2009-1377)

Multiple memory leaks in the dtls1_process_out_of_seq_message function
in ssl/d1_both.c in OpenSSL 0.9.8k and earlier 0.9.8 versions allow
remote attackers to cause a denial of service (memory consumption) via
DTLS records that (1) are duplicates or (2) have sequence numbers much
greater than current sequence numbers, aka DTLS fragment handling
memory leak. (CVE-2009-1378)

Use-after-free vulnerability in the dtls1_retrieve_buffered_fragment
function in ssl/d1_both.c in OpenSSL 1.0.0 Beta 2 allows remote
attackers to cause a denial of service (openssl s_client crash) and
possibly have unspecified other impact via a DTLS packet, as
demonstrated by a packet from a server that uses a crafted server
certificate (CVE-2009-1379).

ssl/s3_pkt.c in OpenSSL before 0.9.8i allows remote attackers to cause
a denial of service (NULL pointer dereference and daemon crash) via a
DTLS ChangeCipherSpec packet that occurs before ClientHello
(CVE-2009-1386).

The dtls1_retrieve_buffered_fragment function in ssl/d1_both.c in
OpenSSL before 1.0.0 Beta 2 allows remote attackers to cause a denial
of service (NULL pointer dereference and daemon crash) via an
out-of-sequence DTLS handshake message, related to a fragment bug.
(CVE-2009-1387)

The NSS library library before 3.12.3, as used in Firefox; GnuTLS
before 2.6.4 and 2.7.4; OpenSSL 0.9.8 through 0.9.8k; and other
products support MD2 with X.509 certificates, which might allow remote
attackers to spooof certificates by using MD2 design flaws to generate
a hash collision in less than brute-force time. NOTE: the scope of
this issue is currently limited because the amount of computation
required is still large (CVE-2009-2409).

A regression was found with the self signed certificate signatures
checking after applying the fix for CVE-2009-2409. An upstream patch
has been applied to address this issue.

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers

The updated packages have been patched to prevent this."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=openssl-cvs&m=124508133203041&w=2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://qa.mandriva.com/54349"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119, 310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openssl0.9.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openssl0.9.8-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openssl0.9.8-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libopenssl0.9.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libopenssl0.9.8-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libopenssl0.9.8-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64openssl0.9.8-0.9.8e-8.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64openssl0.9.8-devel-0.9.8e-8.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64openssl0.9.8-static-devel-0.9.8e-8.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libopenssl0.9.8-0.9.8e-8.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libopenssl0.9.8-devel-0.9.8e-8.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libopenssl0.9.8-static-devel-0.9.8e-8.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"openssl-0.9.8e-8.4mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
