#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2003:010. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(13995);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/31 23:47:33 $");

  script_cve_id("CVE-2003-0034", "CVE-2003-0035", "CVE-2003-0036");
  script_xref(name:"MDKSA", value:"2003:010");

  script_name(english:"Mandrake Linux Security Advisory : printer-drivers (MDKSA-2003:010)");
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
"Karol Wiesek and iDefense disovered three vulnerabilities in the
printer-drivers package and tools it installs. These vulnerabilities
allow a local attacker to empty or create any file on the filesystem.

The first vulnerability is in the mtink binary, which has a buffer
overflow in its handling of the HOME environment variable.

The second vulnerability is in the escputil binary, which has a buffer
overflow in the parsing of the --printer-name command line argument.
This is only possible when esputil is suid or sgid; in Mandrake Linux
9.0 it was sgid 'sys'. Successful exploitation will provide the
attacker with the privilege of the group 'sys'.

The third vulnerability is in the ml85p binary which contains a race
condition in the opening of a temporary file. By default this file is
installed suid root so it can be used to gain root privilege. The only
caveat is that this file is not executable by other, only by root or
group 'sys'. Using either of the two previous vulnerabilities, an
attacker can exploit one of them to obtain 'sys' privilege' and then
use that to exploit this vulnerability to gain root privilege.

MandrakeSoft encourages all users to upgrade immediately.

Aside from the security vulnerabilities, a number of bugfixes are
included in this update, for Mandrake Linux 9.0 users. GIMP-Print
4.2.5pre1, HPIJS 1.3, pnm2ppa 1.12, mtink 0.9.53, and a new foomatic
snapshot are included. For a list of the many bugfixes, please refer
to the RPM changelog."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.idefense.com/advisory/01.21.03.txt"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cups-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:foomatic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ghostscript-module-SVGALIB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ghostscript-module-X");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ghostscript-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gimpprint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgimpprint1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgimpprint1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libijs0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libijs0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:omni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:printer-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:printer-testpages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:printer-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/01/21");
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
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"ghostscript-5.50-67.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"ghostscript-module-SVGALIB-5.50-67.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"ghostscript-module-X-5.50-67.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"ghostscript-utils-5.50-67.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"cups-drivers-1.1-15.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"foomatic-1.1-0.20010923.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"ghostscript-6.51-24.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"ghostscript-module-SVGALIB-6.51-24.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"ghostscript-module-X-6.51-24.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"libgimpprint1-4.1.99-16.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"libgimpprint1-devel-4.1.99-16.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"omni-0.4-11.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"printer-filters-1.0-15.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"printer-testpages-1.0-15.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"printer-utils-1.0-15.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"cups-drivers-1.1-48.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"foomatic-1.1-0.20020323mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"ghostscript-6.53-13.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"ghostscript-module-SVGALIB-6.53-13.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"ghostscript-module-X-6.53-13.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"gimpprint-4.2.1-0.pre5.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"libgimpprint1-4.2.1-0.pre5.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"libgimpprint1-devel-4.2.1-0.pre5.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"omni-0.6.0-2.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"printer-filters-1.0-48.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"printer-testpages-1.0-48.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"printer-utils-1.0-48.2mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"cups-drivers-1.1-84.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"foomatic-2.0.2-20021220.2.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"ghostscript-7.05-33.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"ghostscript-module-X-7.05-33.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"gimpprint-4.2.5-0.2.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"libgimpprint1-4.2.5-0.2.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"libgimpprint1-devel-4.2.5-0.2.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"libijs0-0.34-24.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"libijs0-devel-0.34-24.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"omni-0.7.1-11.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"printer-filters-1.0-84.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"printer-testpages-1.0-84.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"printer-utils-1.0-84.2mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
