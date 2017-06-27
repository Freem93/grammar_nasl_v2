#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2011:103. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(54919);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/06/01 00:15:52 $");

  script_cve_id("CVE-2010-4540", "CVE-2010-4541", "CVE-2010-4542", "CVE-2010-4543", "CVE-2011-1782");
  script_bugtraq_id(45647);
  script_xref(name:"MDVSA", value:"2011:103");

  script_name(english:"Mandriva Linux Security Advisory : gimp (MDVSA-2011:103)");
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
"Multiple vulnerabilities was discovered and fixed in gimp :

Stack-based buffer overflow in the 'LIGHTING EFFECTS > LIGHT' plugin
in GIMP 2.6.11 allows user-assisted remote attackers to cause a denial
of service (application crash) or possibly execute arbitrary code via
a long Position field in a plugin configuration file. NOTE: it may be
uncommon to obtain a GIMP plugin configuration file from an untrusted
source that is separate from the distribution of the plugin itself
(CVE-2010-4540).

Stack-based buffer overflow in the SPHERE DESIGNER plugin in GIMP
2.6.11 allows user-assisted remote attackers to cause a denial of
service (application crash) or possibly execute arbitrary code via a
long Number of lights field in a plugin configuration file. NOTE: it
may be uncommon to obtain a GIMP plugin configuration file from an
untrusted source that is separate from the distribution of the plugin
itself (CVE-2010-4541).

Stack-based buffer overflow in the GFIG plugin in GIMP 2.6.11 allows
user-assisted remote attackers to cause a denial of service
(application crash) or possibly execute arbitrary code via a long
Foreground field in a plugin configuration file. NOTE: it may be
uncommon to obtain a GIMP plugin configuration file from an untrusted
source that is separate from the distribution of the plugin itself
(CVE-2010-4542).

Heap-based buffer overflow in the read_channel_data function in
file-psp.c in the Paint Shop Pro (PSP) plugin in GIMP 2.6.11 allows
remote attackers to cause a denial of service (application crash) or
possibly execute arbitrary code via a PSP_COMP_RLE (aka RLE
compression) image file that begins a long run count at the end of the
image (CVE-2010-4543, CVE-2011-1782).

Packages for 2009.0 are provided as of the Extended Maintenance
Program. Please visit this link to learn more:
http://store.mandriva.com/product_info.php?cPath=149 products_id=490

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gimp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gimp-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gimp2.0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gimp2.0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgimp2.0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgimp2.0_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2009.0", reference:"gimp-2.4.7-1.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"gimp-python-2.4.7-1.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64gimp2.0-devel-2.4.7-1.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64gimp2.0_0-2.4.7-1.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libgimp2.0-devel-2.4.7-1.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libgimp2.0_0-2.4.7-1.2mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.1", reference:"gimp-2.6.8-3.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"gimp-python-2.6.8-3.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64gimp2.0-devel-2.6.8-3.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64gimp2.0_0-2.6.8-3.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libgimp2.0-devel-2.6.8-3.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libgimp2.0_0-2.6.8-3.1mdv2010.2", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
