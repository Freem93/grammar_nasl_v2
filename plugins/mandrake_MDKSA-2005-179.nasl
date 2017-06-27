#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:179. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(20039);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/31 23:51:58 $");

  script_cve_id("CVE-2005-2946", "CVE-2005-2969");
  script_xref(name:"MDKSA", value:"2005:179");

  script_name(english:"Mandrake Linux Security Advisory : openssl (MDKSA-2005:179)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandrake Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Yutaka Oiwa discovered vulnerability potentially affects applications
that use the SSL/TLS server implementation provided by OpenSSL.

Such applications are affected if they use the option
SSL_OP_MSIE_SSLV2_RSA_PADDING. This option is implied by use of
SSL_OP_ALL, which is intended to work around various bugs in third-
party software that might prevent interoperability. The
SSL_OP_MSIE_SSLV2_RSA_PADDING option disables a verification step in
the SSL 2.0 server supposed to prevent active protocol-version
rollback attacks. With this verification step disabled, an attacker
acting as a 'man in the middle' can force a client and a server to
negotiate the SSL 2.0 protocol even if these parties both support SSL
3.0 or TLS 1.0. The SSL 2.0 protocol is known to have severe
cryptographic weaknesses and is supported as a fallback only.
(CVE-2005-2969)

The current default algorithm for creating 'message digests'
(electronic signatures) for certificates created by openssl is MD5.
However, this algorithm is not deemed secure any more, and some
practical attacks have been demonstrated which could allow an attacker
to forge certificates with a valid certification authority signature
even if he does not know the secret CA signing key.

To address this issue, openssl has been changed to use SHA-1 by
default. This is a more appropriate default algorithm for the majority
of use cases. If you still want to use MD5 as default, you can revert
this change by changing the two instances of 'default_md = sha1' to
'default_md = md5' in /usr/{lib,lib64}/ssl/openssl.cnf.
(CVE-2005-2946)"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openssl0.9.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openssl0.9.7-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openssl0.9.7-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libopenssl0.9.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libopenssl0.9.7-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libopenssl0.9.7-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64openssl0.9.7-0.9.7d-1.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64openssl0.9.7-devel-0.9.7d-1.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64openssl0.9.7-static-devel-0.9.7d-1.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libopenssl0.9.7-0.9.7d-1.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libopenssl0.9.7-devel-0.9.7d-1.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libopenssl0.9.7-static-devel-0.9.7d-1.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"openssl-0.9.7d-1.3.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64openssl0.9.7-0.9.7e-5.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64openssl0.9.7-devel-0.9.7e-5.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64openssl0.9.7-static-devel-0.9.7e-5.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libopenssl0.9.7-0.9.7e-5.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libopenssl0.9.7-devel-0.9.7e-5.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libopenssl0.9.7-static-devel-0.9.7e-5.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"openssl-0.9.7e-5.2.102mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64openssl0.9.7-0.9.7g-2.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64openssl0.9.7-devel-0.9.7g-2.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64openssl0.9.7-static-devel-0.9.7g-2.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libopenssl0.9.7-0.9.7g-2.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libopenssl0.9.7-devel-0.9.7g-2.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libopenssl0.9.7-static-devel-0.9.7g-2.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"openssl-0.9.7g-2.1.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
