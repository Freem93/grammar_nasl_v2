#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:038. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(20878);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/31 23:56:38 $");

  script_cve_id("CVE-2004-0969");
  script_xref(name:"MDKSA", value:"2006:038");

  script_name(english:"Mandrake Linux Security Advisory : groff (MDKSA-2006:038)");
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
"The Trustix Secure Linux team discovered a vulnerability in the
groffer utility, part of the groff package. It created a temporary
directory in an insecure way which allowed for the exploitation of a
race condition to create or overwrite files the privileges of the user
invoking groffer.

Likewise, similar temporary file issues were fixed in the pic2graph
and eqn2graph programs which now use mktemp to create temporary files,
as discovered by Javier Fernandez-Sanguino Pena.

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:groff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:groff-for-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:groff-gxditview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:groff-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.1", reference:"groff-1.19-6.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"groff-for-man-1.19-6.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"groff-gxditview-1.19-6.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"groff-perl-1.19-6.1.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", reference:"groff-1.19-9.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"groff-for-man-1.19-9.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"groff-gxditview-1.19-9.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"groff-perl-1.19-9.1.102mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2006.0", reference:"groff-1.19.1-1.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"groff-for-man-1.19.1-1.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"groff-gxditview-1.19.1-1.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"groff-perl-1.19.1-1.1.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
