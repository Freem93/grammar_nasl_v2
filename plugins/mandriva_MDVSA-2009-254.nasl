#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:254. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(41961);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/03/19 14:49:28 $");

  script_cve_id("CVE-2008-4555");
  script_bugtraq_id(31648);
  script_xref(name:"MDVSA", value:"2009:254-1");

  script_name(english:"Mandriva Linux Security Advisory : graphviz (MDVSA-2009:254-1)");
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
"A vulnerability was discovered and corrected in graphviz :

Stack-based buffer overflow in the push_subg function in parser.y
(lib/graph/parser.c) in Graphviz 2.20.2, and possibly earlier
versions, allows user-assisted remote attackers to cause a denial of
service (memory corruption) or execute arbitrary code via a DOT file
with a large number of Agraph_t elements (CVE-2008-4555).

This update provides a fix for this vulnerability.

Update :

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:graphviz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:graphviz-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64graphviz-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64graphviz-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64graphviz3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64graphvizlua0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64graphvizperl0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64graphvizphp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64graphvizpython0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64graphvizruby0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64graphviztcl0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgraphviz-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgraphviz-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgraphviz3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgraphvizlua0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgraphvizperl0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgraphvizphp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgraphvizpython0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgraphvizruby0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgraphviztcl0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.0", reference:"graphviz-2.12-6.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"graphviz-doc-2.12-6.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64graphviz-devel-2.12-6.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64graphviz-static-devel-2.12-6.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64graphviz3-2.12-6.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64graphvizlua0-2.12-6.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64graphvizperl0-2.12-6.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64graphvizphp0-2.12-6.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64graphvizpython0-2.12-6.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64graphvizruby0-2.12-6.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64graphviztcl0-2.12-6.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libgraphviz-devel-2.12-6.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libgraphviz-static-devel-2.12-6.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libgraphviz3-2.12-6.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libgraphvizlua0-2.12-6.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libgraphvizperl0-2.12-6.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libgraphvizphp0-2.12-6.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libgraphvizpython0-2.12-6.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libgraphvizruby0-2.12-6.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libgraphviztcl0-2.12-6.1mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
