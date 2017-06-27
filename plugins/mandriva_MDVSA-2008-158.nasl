#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2008:158. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(36632);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/28 21:39:22 $");

  script_cve_id("CVE-2008-1227", "CVE-2008-1552");
  script_xref(name:"MDVSA", value:"2008:158");

  script_name(english:"Mandriva Linux Security Advisory : silc-toolkit (MDVSA-2008:158)");
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
"A vulnerability was found in the SILC toolkit before version 1.1.5
that allowed a remote attacker to cause a denial of service (crash),
or possibly execute arbitrary code via long input data
(CVE-2008-1227).

A vulnerability was found in the SILC toolkit before version 1.1.7
that allowed a remote attacker to execute arbitrary code via a crafted
PKCS#2 message (CVE-2008-1552).

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64silc-1.1_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64silcclient-1.1_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsilc-1.1_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsilcclient-1.1_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:silc-toolkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:silc-toolkit-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64silc-1.1_2-1.1.2-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64silcclient-1.1_2-1.1.2-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libsilc-1.1_2-1.1.2-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libsilcclient-1.1_2-1.1.2-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"silc-toolkit-1.1.2-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"silc-toolkit-devel-1.1.2-2.1mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
