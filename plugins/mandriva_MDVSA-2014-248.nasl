#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:248. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(79993);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/12/16 15:13:15 $");

  script_cve_id("CVE-2014-9157");
  script_bugtraq_id(71283);
  script_xref(name:"MDVSA", value:"2014:248");

  script_name(english:"Mandriva Linux Security Advisory : graphviz (MDVSA-2014:248)");
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
"Updated graphviz packages fix security vulnerability :

Format string vulnerability in the yyerror function in
lib/cgraph/scan.l in Graphviz allows remote attackers to have
unspecified impact via format string specifiers in unknown vector,
which are not properly handled in an error string (CVE-2014-9157)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0520.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:graphviz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:graphviz-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-graphviz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64cdt5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64cgraph6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64graph5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64graphviz-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64graphviz-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gvc6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gvpr2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64pathplan4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xdot4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lua-graphviz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ocaml-graphviz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-graphviz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-graphviz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-graphviz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-graphviz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tcl-graphviz");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"graphviz-2.28.0-6.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"graphviz-doc-2.28.0-6.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"java-graphviz-2.28.0-6.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64cdt5-2.28.0-6.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64cgraph6-2.28.0-6.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64graph5-2.28.0-6.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64graphviz-devel-2.28.0-6.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64graphviz-static-devel-2.28.0-6.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64gvc6-2.28.0-6.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64gvpr2-2.28.0-6.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64pathplan4-2.28.0-6.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64xdot4-2.28.0-6.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lua-graphviz-2.28.0-6.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"ocaml-graphviz-2.28.0-6.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"perl-graphviz-2.28.0-6.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-graphviz-2.28.0-6.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"python-graphviz-2.28.0-6.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"ruby-graphviz-2.28.0-6.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"tcl-graphviz-2.28.0-6.2.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
