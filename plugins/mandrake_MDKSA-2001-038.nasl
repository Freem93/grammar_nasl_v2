#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2001:038. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(61911);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/05/22 11:11:55 $");

  script_xref(name:"MDKSA", value:"2001:038");

  script_name(english:"Mandrake Linux Security Advisory : netscape (MDKSA-2001:038)");
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
"A vulnerability exists in versions of Netscape prior to 4.77 that
allow a remote web server that the user is accessing to obtain
information about the client using Netscape's internal 'about:'
protocol. Other internal protocols can be accessed this way, such as
the 'about:global' protocol which will display the browser history, or
the 'about:config' protocol which will display the browser
configuration. These problems are directly related to JavaScript
processing embedded commands in GIF files which Netscape does not
properly escape, and can be negated by disabling JavaScript in
Netscape. However it is recommended that all users upgrade to version
4.77."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:netscape-castellano");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:netscape-catalan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:netscape-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:netscape-communicator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:netscape-euskara");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:netscape-francais");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:netscape-german");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:netscape-japanese");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:netscape-navigator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:netscape-polish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:netscape-russian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:netscape-walon");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK7.1", reference:"netscape-castellano-4.77-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", reference:"netscape-catalan-4.77-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"netscape-common-4.77-4.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"netscape-communicator-4.77-4.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", reference:"netscape-euskara-4.77-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", reference:"netscape-francais-4.77-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"netscape-navigator-4.77-4.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", reference:"netscape-russian-4.77-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", reference:"netscape-walon-4.77-1.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK7.2", reference:"netscape-castellano-4.77-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", reference:"netscape-catalan-4.77-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"netscape-common-4.77-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"netscape-communicator-4.77-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", reference:"netscape-euskara-4.77-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", reference:"netscape-francais-4.77-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", reference:"netscape-german-4.77-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", reference:"netscape-japanese-4.77-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"netscape-navigator-4.77-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", reference:"netscape-polish-4.77-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", reference:"netscape-russian-4.77-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", reference:"netscape-walon-4.77-1.1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
