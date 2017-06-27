#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2001:086. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(13899);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/31 23:43:25 $");

  script_cve_id("CVE-2001-0906");
  script_xref(name:"MDKSA", value:"2001:086");

  script_name(english:"Mandrake Linux Security Advisory : tetex (MDKSA-2001:086)");
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
"A problem was discovered in the temporary file handling capabilities
of some teTeX filters by zen-parse. These filters are used as print
filters automatically when printing .dvi files using lpr. This can
lead to elevated privileges. This update relies on the updated mktemp
packages for 7.x in MDKA-2001:021, which gives mktemp the ability to
create temporary directories. 8.x users already have a mktemp that
works in this fashion."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/192647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=43342"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-afm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-dvilj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-dvipdfm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-dvips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-xdvi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/11/20");
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
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"tetex-1.0.7-6.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"tetex-afm-1.0.7-6.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"tetex-doc-1.0.7-6.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"tetex-dvilj-1.0.7-6.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"tetex-dvips-1.0.7-6.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"tetex-latex-1.0.7-6.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"tetex-xdvi-1.0.7-6.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"tetex-1.0.7-11.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"tetex-afm-1.0.7-11.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"tetex-doc-1.0.7-11.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"tetex-dvilj-1.0.7-11.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"tetex-dvips-1.0.7-11.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"tetex-latex-1.0.7-11.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"tetex-xdvi-1.0.7-11.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"tetex-1.0.7-21.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"tetex-afm-1.0.7-21.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"tetex-doc-1.0.7-21.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"tetex-dvilj-1.0.7-21.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"tetex-dvipdfm-1.0.7-21.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"tetex-dvips-1.0.7-21.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"tetex-latex-1.0.7-21.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"tetex-xdvi-1.0.7-21.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"tetex-1.0.7-31.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"tetex-afm-1.0.7-31.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"tetex-doc-1.0.7-31.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"tetex-dvilj-1.0.7-31.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"tetex-dvipdfm-1.0.7-31.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"tetex-dvips-1.0.7-31.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"tetex-latex-1.0.7-31.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"tetex-xdvi-1.0.7-31.1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
