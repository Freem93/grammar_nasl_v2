#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:054. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(17332);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:51:56 $");

  script_cve_id("CVE-2005-0373");
  script_xref(name:"MDKSA", value:"2005:054");

  script_name(english:"Mandrake Linux Security Advisory : cyrus-sasl (MDKSA-2005:054)");
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
"A buffer overflow was discovered in cyrus-sasl's digestmd5 code. This
could lead to a remote attacker executing code in the context of the
service using SASL authentication. This vulnerability was fixed
upstream in version 2.1.19.

The updated packages are patched to deal with this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cyrus-sasl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sasl2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sasl2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sasl2-plug-anonymous");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sasl2-plug-crammd5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sasl2-plug-digestmd5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sasl2-plug-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sasl2-plug-login");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sasl2-plug-ntlm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sasl2-plug-otp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sasl2-plug-plain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sasl2-plug-sasldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sasl2-plug-srp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl2-plug-anonymous");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl2-plug-crammd5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl2-plug-digestmd5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl2-plug-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl2-plug-login");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl2-plug-ntlm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl2-plug-otp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl2-plug-plain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl2-plug-sasldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl2-plug-srp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/16");
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
if (rpm_check(release:"MDK10.0", reference:"cyrus-sasl-2.1.15-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64sasl2-2.1.15-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64sasl2-devel-2.1.15-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64sasl2-plug-anonymous-2.1.15-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64sasl2-plug-crammd5-2.1.15-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64sasl2-plug-digestmd5-2.1.15-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64sasl2-plug-gssapi-2.1.15-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64sasl2-plug-login-2.1.15-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64sasl2-plug-ntlm-2.1.15-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64sasl2-plug-otp-2.1.15-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64sasl2-plug-plain-2.1.15-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64sasl2-plug-sasldb-2.1.15-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64sasl2-plug-srp-2.1.15-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libsasl2-2.1.15-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libsasl2-devel-2.1.15-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libsasl2-plug-anonymous-2.1.15-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libsasl2-plug-crammd5-2.1.15-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libsasl2-plug-digestmd5-2.1.15-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libsasl2-plug-gssapi-2.1.15-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libsasl2-plug-login-2.1.15-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libsasl2-plug-ntlm-2.1.15-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libsasl2-plug-otp-2.1.15-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libsasl2-plug-plain-2.1.15-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libsasl2-plug-sasldb-2.1.15-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libsasl2-plug-srp-2.1.15-10.2.100mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
