#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:080. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(45565);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/06/01 00:11:07 $");

  script_cve_id("CVE-2008-3279");
  script_bugtraq_id(39097);
  script_xref(name:"MDVSA", value:"2010:080");

  script_name(english:"Mandriva Linux Security Advisory : brltty (MDVSA-2010:080)");
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
"A vulnerability has been found and corrected in brltty :

Untrusted search path vulnerability in libbrlttybba.so in brltty 3.7.2
allows local users to gain privileges via a crafted library, related
to an incorrect RPATH setting (CVE-2008-3279).

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers.

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:brltty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64brlapi0.4.1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64brlapi0.4.1_0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libbrlapi0.4.1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libbrlapi0.4.1_0-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/19");
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
if (rpm_check(release:"MDK2008.0", reference:"brltty-3.7.2-6.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64brlapi0.4.1_0-3.7.2-6.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64brlapi0.4.1_0-devel-3.7.2-6.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libbrlapi0.4.1_0-3.7.2-6.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libbrlapi0.4.1_0-devel-3.7.2-6.1mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
