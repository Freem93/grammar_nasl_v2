#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:094. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14750);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/05/31 23:47:35 $");

  script_cve_id("CVE-2004-0801");
  script_xref(name:"MDKSA", value:"2004:094");

  script_name(english:"Mandrake Linux Security Advisory : printer-drivers (MDKSA-2004:094)");
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
"The foomatic-rip filter, which is part of foomatic-filters package,
contains a vulnerability that allows anyone with access to CUPS, local
or remote, to execute arbitrary commands on the server. The updated
packages provide a fixed foomatic-rip filter that prevents this kind
of abuse."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cups-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:foomatic-db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:foomatic-db-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:foomatic-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ghostscript-module-X");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gimpprint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gimpprint1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gimpprint1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ijs0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ijs0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgimpprint1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgimpprint1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libijs0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libijs0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:omni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:printer-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:printer-testpages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:printer-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/16");
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
if (rpm_check(release:"MDK10.0", reference:"cups-drivers-1.1-138.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"foomatic-db-3.0.1-0.20040828.1.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"foomatic-db-engine-3.0.1-0.20040828.1.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"foomatic-filters-3.0.1-0.20040828.1.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"ghostscript-7.07-19.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"ghostscript-module-X-7.07-19.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"gimpprint-4.2.7-2.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64gimpprint1-4.2.7-2.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64gimpprint1-devel-4.2.7-2.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64ijs0-0.34-76.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64ijs0-devel-0.34-76.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libgimpprint1-4.2.7-2.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libgimpprint1-devel-4.2.7-2.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libijs0-0.34-76.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libijs0-devel-0.34-76.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"printer-filters-1.0-138.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"printer-testpages-1.0-138.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"printer-utils-1.0-138.2.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", reference:"cups-drivers-1.1-116.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"foomatic-db-3.0-1.20030908.3.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"foomatic-db-engine-3.0-1.20030908.3.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"foomatic-filters-3.0-1.20030908.3.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"ghostscript-7.07-0.12.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"ghostscript-module-X-7.07-0.12.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"gimpprint-4.2.5-30.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64gimpprint1-4.2.5-30.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64gimpprint1-devel-4.2.5-30.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64ijs0-0.34-56.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64ijs0-devel-0.34-56.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libgimpprint1-4.2.5-30.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libgimpprint1-devel-4.2.5-30.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libijs0-0.34-56.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libijs0-devel-0.34-56.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"omni-0.7.2-32.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"printer-filters-1.0-116.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"printer-testpages-1.0-116.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"printer-utils-1.0-116.1.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
