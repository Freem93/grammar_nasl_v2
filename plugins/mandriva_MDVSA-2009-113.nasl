#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:113. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(38814);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/06/01 00:06:03 $");

  script_cve_id("CVE-2009-0688");
  script_xref(name:"MDVSA", value:"2009:113-1");

  script_name(english:"Mandriva Linux Security Advisory : cyrus-sasl (MDVSA-2009:113-1)");
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
"Multiple buffer overflows in the CMU Cyrus SASL library before 2.1.23
might allow remote attackers to execute arbitrary code or cause a
denial of service application crash) via strings that are used as
input to the sasl_encode64 function in lib/saslutil.c (CVE-2009-0688).

The updated packages have been patched to prevent this.

Update :

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cyrus-sasl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sasl2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sasl2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sasl2-plug-anonymous");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sasl2-plug-crammd5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sasl2-plug-digestmd5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sasl2-plug-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sasl2-plug-ldapdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sasl2-plug-login");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sasl2-plug-ntlm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sasl2-plug-otp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sasl2-plug-plain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sasl2-plug-sasldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sasl2-plug-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl2-plug-anonymous");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl2-plug-crammd5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl2-plug-digestmd5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl2-plug-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl2-plug-ldapdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl2-plug-login");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl2-plug-ntlm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl2-plug-otp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl2-plug-plain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl2-plug-sasldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl2-plug-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.0", reference:"cyrus-sasl-2.1.22-23.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64sasl2-2.1.22-23.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64sasl2-devel-2.1.22-23.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64sasl2-plug-anonymous-2.1.22-23.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64sasl2-plug-crammd5-2.1.22-23.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64sasl2-plug-digestmd5-2.1.22-23.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64sasl2-plug-gssapi-2.1.22-23.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64sasl2-plug-ldapdb-2.1.22-23.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64sasl2-plug-login-2.1.22-23.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64sasl2-plug-ntlm-2.1.22-23.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64sasl2-plug-otp-2.1.22-23.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64sasl2-plug-plain-2.1.22-23.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64sasl2-plug-sasldb-2.1.22-23.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64sasl2-plug-sql-2.1.22-23.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libsasl2-2.1.22-23.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libsasl2-devel-2.1.22-23.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libsasl2-plug-anonymous-2.1.22-23.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libsasl2-plug-crammd5-2.1.22-23.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libsasl2-plug-digestmd5-2.1.22-23.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libsasl2-plug-gssapi-2.1.22-23.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libsasl2-plug-ldapdb-2.1.22-23.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libsasl2-plug-login-2.1.22-23.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libsasl2-plug-ntlm-2.1.22-23.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libsasl2-plug-otp-2.1.22-23.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libsasl2-plug-plain-2.1.22-23.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libsasl2-plug-sasldb-2.1.22-23.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libsasl2-plug-sql-2.1.22-23.1mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
