#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2003:092. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14074);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/01/14 15:43:29 $");

  script_cve_id("CVE-2003-0681", "CVE-2003-0694");
  script_xref(name:"MDKSA", value:"2003:092");

  script_name(english:"Mandrake Linux Security Advisory : sendmail (MDKSA-2003:092)");
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
"A buffer overflow vulnerability was discovered in the address parsing
code in all versions of sendmail prior to 8.12.10 by Michal Zalewski,
with a patch to fix the problem provided by Todd C. Miller. This
vulnerability seems to be remotely exploitable on Linux systems
running on the x86 platform; the sendmail team is unsure of other
platforms (CVE-2003-0694).

Another potential buffer overflow was fixed in ruleset parsing which
is not exploitable in the default sendmail configuration. A problem
may occur if non-standard rulesets recipient (2), final (4), or
mailer- specific envelope recipients rulesets are use. This problem
was discovered by Timo Sirainen (CVE-2003-0681).

MandrakeSoft encourages all users who use sendmail to upgrade to the
provided packages which are patched to fix both problems."
  );
  # http://lists.netsys.com/pipermail/full-disclosure/2003-September/010287.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?abda8564"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.sendmail.org/8.12.10.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:sendmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:sendmail-cf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:sendmail-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:sendmail-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/09/17");
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
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"sendmail-8.12.1-4.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"sendmail-cf-8.12.1-4.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"sendmail-devel-8.12.1-4.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"sendmail-doc-8.12.1-4.5mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"sendmail-8.12.6-3.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"sendmail-cf-8.12.6-3.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"sendmail-devel-8.12.6-3.5mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"sendmail-doc-8.12.6-3.5mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"sendmail-8.12.9-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"sendmail-cf-8.12.9-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"sendmail-devel-8.12.9-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"sendmail-doc-8.12.9-1.2mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
