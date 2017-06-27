#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:039. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(44650);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/11/14 14:27:59 $");

  script_cve_id("CVE-2009-4274");
  script_bugtraq_id(38164);
  script_xref(name:"MDVSA", value:"2010:039");

  script_name(english:"Mandriva Linux Security Advisory : netpbm (MDVSA-2010:039)");
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
"A vulnerability have been discovered and corrected in netpbm :

Stack-based buffer overflow in converter/ppm/xpmtoppm.c in netpbm
before 10.47.07 allows context-dependent attackers to cause a denial
of service (application crash) or possibly execute arbitrary code via
an XPM image file that contains a crafted header field associated with
a large color index value (CVE-2009-4274).

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers.

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64netpbm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64netpbm-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64netpbm10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnetpbm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnetpbm-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnetpbm10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:netpbm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64netpbm-devel-10.34-8.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64netpbm-static-devel-10.34-8.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64netpbm10-10.34-8.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libnetpbm-devel-10.34-8.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libnetpbm-static-devel-10.34-8.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libnetpbm10-10.34-8.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"netpbm-10.34-8.4mdv2008.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64netpbm-devel-10.35.46-1.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64netpbm-static-devel-10.35.46-1.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64netpbm10-10.35.46-1.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libnetpbm-devel-10.35.46-1.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libnetpbm-static-devel-10.35.46-1.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libnetpbm10-10.35.46-1.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"netpbm-10.35.46-1.2mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64netpbm-devel-10.35.59-1.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64netpbm-static-devel-10.35.59-1.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64netpbm10-10.35.59-1.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libnetpbm-devel-10.35.59-1.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libnetpbm-static-devel-10.35.59-1.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libnetpbm10-10.35.59-1.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"netpbm-10.35.59-1.1mdv2009.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64netpbm-devel-10.35.64-4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64netpbm-static-devel-10.35.64-4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64netpbm10-10.35.64-4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libnetpbm-devel-10.35.64-4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libnetpbm-static-devel-10.35.64-4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libnetpbm10-10.35.64-4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"netpbm-10.35.64-4.1mdv2010.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
