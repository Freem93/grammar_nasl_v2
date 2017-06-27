#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2003:098. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14080);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2015/09/01 13:42:18 $");

  script_cve_id("CVE-2003-0543", "CVE-2003-0544", "CVE-2003-0545");
  script_xref(name:"CERT", value:"255484");
  script_xref(name:"CERT", value:"380864");
  script_xref(name:"CERT", value:"935264");
  script_xref(name:"MDKSA", value:"2003:098");

  script_name(english:"Mandrake Linux Security Advisory : openssl (MDKSA-2003:098)");
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
"Two bugs were discovered in OpenSSL 0.9.6 and 0.9.7 by NISCC. The
parsing of unusual ASN.1 tag values can cause OpenSSL to crash, which
could be triggered by a remote attacker by sending a carefully-crafted
SSL client certificate to an application. Depending upon the
application targetted, the effects seen will vary; in some cases a DoS
(Denial of Service) could be performed, in others nothing noticeable
or adverse may happen. These two vulnerabilities have been assigned
CVE-2003-0543 and CVE-2003-0544.

Additionally, NISCC discovered a third bug in OpenSSL 0.9.7. Certain
ASN.1 encodings that are rejected as invalid by the parser can trigger
a bug in deallocation of a structure, leading to a double free. This
can be triggered by a remote attacker by sending a carefully-crafted
SSL client certificate to an application. This vulnerability may be
exploitable to execute arbitrary code. This vulnerability has been
assigned CVE-2003-0545.

The packages provided have been built with patches provided by the
OpenSSL group that resolve these issues.

A number of server applications such as OpenSSH and Apache that make
use of OpenSSL need to be restarted after the update has been applied
to ensure that they are protected from these issues. Users are
encouraged to restart all of these services or reboot their systems."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openssl.org/news/secadv/20030930.txt"
  );
  # http://www.uniras.gov.uk/vuls/2003/006489/openssl.htm
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=openssl-dev&m=108445413725636"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.uniras.gov.uk/vuls/2003/006489/tls.htm"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openssl0.9.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openssl0.9.7-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openssl0.9.7-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libopenssl0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libopenssl0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libopenssl0-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libopenssl0.9.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libopenssl0.9.7-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libopenssl0.9.7-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"libopenssl0-0.9.6i-1.5.82mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"libopenssl0-devel-0.9.6i-1.5.82mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"libopenssl0-static-devel-0.9.6i-1.5.82mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"openssl-0.9.6i-1.5.82mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"libopenssl0-0.9.6i-1.6.90mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"libopenssl0-devel-0.9.6i-1.6.90mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"libopenssl0-static-devel-0.9.6i-1.6.90mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"openssl-0.9.6i-1.6.90mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"libopenssl0-0.9.6i-1.2.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"libopenssl0.9.7-0.9.7a-1.2.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"libopenssl0.9.7-devel-0.9.7a-1.2.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"libopenssl0.9.7-static-devel-0.9.7a-1.2.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"openssl-0.9.7a-1.2.91mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64openssl0.9.7-0.9.7b-5.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64openssl0.9.7-devel-0.9.7b-5.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64openssl0.9.7-static-devel-0.9.7b-5.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libopenssl0.9.7-0.9.7b-4.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libopenssl0.9.7-devel-0.9.7b-4.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libopenssl0.9.7-static-devel-0.9.7b-4.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"openssl-0.9.7b-5.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"openssl-0.9.7b-4.1.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
