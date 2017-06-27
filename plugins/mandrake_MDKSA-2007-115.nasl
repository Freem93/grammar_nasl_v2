#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:115. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(25432);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/06/01 00:01:20 $");

  script_cve_id("CVE-2007-2650", "CVE-2007-3023", "CVE-2007-3024", "CVE-2007-3025", "CVE-2007-3122", "CVE-2007-3123");
  script_xref(name:"MDKSA", value:"2007:115");

  script_name(english:"Mandrake Linux Security Advisory : clamav (MDKSA-2007:115)");
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
"A vulnerability in the OLE2 parser in ClamAV was found that could
allow a remote attacker to cause a denial of service via resource
consumption with a carefully crafted OLE2 file.

Other vulnerabilities and bugs have also been corrected in 0.90.3
which is being provided with this update."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:clamav-db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:clamav-milter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:clamd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:clamdmon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64clamav2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64clamav2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libclamav2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libclamav2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/05");
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
if (rpm_check(release:"MDK2007.0", reference:"clamav-0.90.3-0.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"clamav-db-0.90.3-0.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"clamav-milter-0.90.3-0.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"clamd-0.90.3-0.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"clamdmon-0.90.3-0.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64clamav2-0.90.3-0.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64clamav2-devel-0.90.3-0.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libclamav2-0.90.3-0.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libclamav2-devel-0.90.3-0.1mdv2007.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2007.1", reference:"clamav-0.90.3-0.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"clamav-db-0.90.3-0.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"clamav-milter-0.90.3-0.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"clamd-0.90.3-0.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"clamdmon-0.90.3-0.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64clamav2-0.90.3-0.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64clamav2-devel-0.90.3-0.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libclamav2-0.90.3-0.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libclamav2-devel-0.90.3-0.1mdv2007.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
