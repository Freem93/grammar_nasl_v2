#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2002:038. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(13943);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2013/05/31 23:43:26 $");

  script_cve_id("CVE-2002-0400", "CVE-2002-0651");
  script_xref(name:"CERT", value:"739123");
  script_xref(name:"CERT", value:"803539");
  script_xref(name:"MDKSA", value:"2002:038-1");

  script_name(english:"Mandrake Linux Security Advisory : bind (MDKSA-2002:038-1)");
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
"A vulnerability was discovered in the BIND9 DNS server in versions
prior to 9.2.1. An error condition will trigger the shutdown of the
server when the rdataset parameter to the dns_message_findtype()
function in message.c is not NULL as expected. This condition causes
the server to assert an error message and shutdown the BIND server.
The error condition can be remotely exploited by a special DNS packet.
This can only be used to create a Denial of Service on the server; the
error condition is correctly detected, so it will not allow an
attacker to execute arbitrary code on the server.

Update :

Sascha Kettler noticed that the version of BIND9 supplied originally
was in fact 9.2.1RC1 and mis-labelled as 9.2.1. The packages provided
in this update are BIND 9.2.1 final. Likewise, the buffer overflow in
the DNS resolver libraries, as noted in MDKSA-2002:043, has also been
fixed. Thanks to Bernhard Rosenkraenzer at Red Hat for backporting the
patches from 8.3.3 to 9.2.1."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:caching-nameserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"bind-9.2.1-2.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"bind-devel-9.2.1-2.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"bind-utils-9.2.1-2.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", reference:"caching-nameserver-8.1-3.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"bind-9.2.1-2.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"bind-devel-9.2.1-2.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"bind-utils-9.2.1-2.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", reference:"caching-nameserver-8.1-3.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"bind-9.2.1-2.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"bind-devel-9.2.1-2.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"bind-utils-9.2.1-2.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", reference:"caching-nameserver-8.1-3.1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
