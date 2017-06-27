#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:061. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(17658);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2014/04/15 10:48:38 $");

  script_cve_id("CVE-2005-0468", "CVE-2005-0469");
  script_xref(name:"MDKSA", value:"2005:061");

  script_name(english:"Mandrake Linux Security Advisory : krb5 (MDKSA-2005:061)");
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
"Two buffer overflow issues were discovered in the way telnet clients
handle messages from a server. Because of these issues, an attacker
may be able to execute arbitrary code on the victim's machine if the
victim can be tricked into connecting to a malicious telnet server.
The Kerberos package contains a telnet client and is patched to deal
with these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2005-001-telnet.txt"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ftp-client-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ftp-server-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64krb51");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64krb51-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64krb53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64krb53-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkrb51");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkrb51-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkrb53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkrb53-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:telnet-client-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:telnet-server-krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.0", reference:"ftp-client-krb5-1.3-6.5.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"ftp-server-krb5-1.3-6.5.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"krb5-server-1.3-6.5.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"krb5-workstation-1.3-6.5.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64krb51-1.3-6.5.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64krb51-devel-1.3-6.5.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libkrb51-1.3-6.5.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libkrb51-devel-1.3-6.5.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"telnet-client-krb5-1.3-6.5.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"telnet-server-krb5-1.3-6.5.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"ftp-client-krb5-1.3.4-2.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"ftp-server-krb5-1.3.4-2.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"krb5-server-1.3.4-2.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"krb5-workstation-1.3.4-2.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64krb53-1.3.4-2.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64krb53-devel-1.3.4-2.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libkrb53-1.3.4-2.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libkrb53-devel-1.3.4-2.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"telnet-client-krb5-1.3.4-2.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"telnet-server-krb5-1.3.4-2.2.101mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
