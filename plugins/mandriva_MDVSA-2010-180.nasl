#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:180. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(49209);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/06/01 00:15:50 $");

  script_cve_id("CVE-2005-4889", "CVE-2010-2059");
  script_bugtraq_id(40512);
  script_xref(name:"MDVSA", value:"2010:180");

  script_name(english:"Mandriva Linux Security Advisory : rpm (MDVSA-2010:180)");
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
"A vulnerability has been found and corrected in rpm :

lib/fsm.c in RPM 4.8.0 and unspecified 4.7.x and 4.6.x versions, and
RPM before 4.4.3, does not properly reset the metadata of an
executable file during replacement of the file in an RPM package
upgrade, which might allow local users to gain privileges by creating
a hard link to a vulnerable (1) setuid or (2) setgid file
(CVE-2010-2059).

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64popt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64popt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64rpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64rpm4.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpopt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpopt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:librpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:librpm4.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:popt-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rpm-build");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/13");
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
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64popt-devel-1.10.8-32.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64popt0-1.10.8-32.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64rpm-devel-4.4.2.3-20.1mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64rpm4.4-4.4.2.3-20.1mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libpopt-devel-1.10.8-32.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libpopt0-1.10.8-32.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"librpm-devel-4.4.2.3-20.1mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"librpm4.4-4.4.2.3-20.1mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"popt-data-1.10.8-32.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"python-rpm-4.4.2.3-20.1mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"rpm-4.4.2.3-20.1mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"rpm-build-4.4.2.3-20.1mnb2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
