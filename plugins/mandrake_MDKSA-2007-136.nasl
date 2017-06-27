#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:136. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(25602);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/06/01 00:01:20 $");

  script_cve_id("CVE-2007-3257");
  script_xref(name:"MDKSA", value:"2007:136");

  script_name(english:"Mandrake Linux Security Advisory : evolution (MDKSA-2007:136)");
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
"A flaw in Evolution/evolution-data-server was found in how Evolution
would process certain IMAP server messages. If a user were tricked
into connecting to a malicious IMAP server, it was possible that
arbitrary code could be executed with the privileges of the user using
Evolution.

Updated packages have been patched to prevent this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:evolution-data-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64camel-provider10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64camel-provider8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64camel0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64camel10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ebook9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ecal7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64edata-book2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64edata-cal6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64edataserver7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64edataserver7-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64edataserver9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64edataserver9-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64edataserverui8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64egroupwise12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64egroupwise13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64exchange-storage2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64exchange-storage3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libcamel-provider10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libcamel-provider8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libcamel0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libcamel10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libebook9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libecal7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libedata-book2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libedata-cal6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libedataserver7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libedataserver7-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libedataserver9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libedataserver9-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libedataserverui8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libegroupwise12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libegroupwise13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libexchange-storage2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libexchange-storage3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2007.0", reference:"evolution-data-server-1.8.0-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64camel-provider8-1.8.0-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64camel0-1.8.0-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64ebook9-1.8.0-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64ecal7-1.8.0-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64edata-book2-1.8.0-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64edata-cal6-1.8.0-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64edataserver7-1.8.0-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64edataserver7-devel-1.8.0-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64edataserverui8-1.8.0-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64egroupwise12-1.8.0-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64exchange-storage2-1.8.0-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libcamel-provider8-1.8.0-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libcamel0-1.8.0-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libebook9-1.8.0-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libecal7-1.8.0-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libedata-book2-1.8.0-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libedata-cal6-1.8.0-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libedataserver7-1.8.0-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libedataserver7-devel-1.8.0-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libedataserverui8-1.8.0-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libegroupwise12-1.8.0-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libexchange-storage2-1.8.0-1.2mdv2007.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2007.1", reference:"evolution-data-server-1.10.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64camel-provider10-1.10.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64camel10-1.10.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64ebook9-1.10.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64ecal7-1.10.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64edata-book2-1.10.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64edata-cal6-1.10.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64edataserver9-1.10.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64edataserver9-devel-1.10.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64edataserverui8-1.10.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64egroupwise13-1.10.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64exchange-storage3-1.10.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libcamel-provider10-1.10.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libcamel10-1.10.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libebook9-1.10.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libecal7-1.10.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libedata-book2-1.10.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libedata-cal6-1.10.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libedataserver9-1.10.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libedataserver9-devel-1.10.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libedataserverui8-1.10.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libegroupwise13-1.10.2-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libexchange-storage3-1.10.2-1.2mdv2007.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
