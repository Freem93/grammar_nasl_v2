#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:071. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(18052);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:51:57 $");

  script_cve_id("CVE-2005-0965", "CVE-2005-0966", "CVE-2005-0967");
  script_xref(name:"MDKSA", value:"2005:071");

  script_name(english:"Mandrake Linux Security Advisory : gaim (MDKSA-2005:071)");
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
"More vulnerabilities have been discovered in the gaim instant
messaging client :

A buffer overflow vulnerability was found in the way that gaim escapes
HTML, allowing a remote attacker to send a specially crafted message
to a gaim client and causing it to crash (CVE-2005-0965).

A bug was discovered in several of gaim's IRC processing functions
that fail to properly remove various markup tags within an IRC
message. This could allow a remote attacker to send specially crafted
message to a gaim client connected to an IRC server, causing it to
crash (CVE-2005-0966).

Finally, a problem was found in gaim's Jabber message parser that
would allow a remote Jabber user to send a specially crafted message
to a gaim client, bausing it to crash (CVE-2005-0967).

Gaim version 1.2.1 is not vulnerable to these issues and is provided
with this update."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gaim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gaim-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gaim-gevolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gaim-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gaim-silc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gaim-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gaim-remote0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gaim-remote0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgaim-remote0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgaim-remote0-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/15");
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
if (rpm_check(release:"MDK10.1", reference:"gaim-1.2.1-0.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"gaim-devel-1.2.1-0.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"gaim-gevolution-1.2.1-0.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"gaim-perl-1.2.1-0.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"gaim-tcl-1.2.1-0.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64gaim-remote0-1.2.1-0.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64gaim-remote0-devel-1.2.1-0.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libgaim-remote0-1.2.1-0.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libgaim-remote0-devel-1.2.1-0.1.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", reference:"gaim-1.2.1-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"gaim-devel-1.2.1-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"gaim-gevolution-1.2.1-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"gaim-perl-1.2.1-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"gaim-silc-1.2.1-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"gaim-tcl-1.2.1-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64gaim-remote0-1.2.1-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64gaim-remote0-devel-1.2.1-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libgaim-remote0-1.2.1-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libgaim-remote0-devel-1.2.1-0.1.102mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
