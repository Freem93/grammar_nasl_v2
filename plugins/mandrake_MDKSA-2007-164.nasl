#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:164. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(25896);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/11/28 21:39:21 $");

  script_cve_id("CVE-2007-3387", "CVE-2007-3472", "CVE-2007-3473", "CVE-2007-3474", "CVE-2007-3475", "CVE-2007-3476", "CVE-2007-3477", "CVE-2007-3478");
  script_xref(name:"MDKSA", value:"2007:164");

  script_name(english:"Mandrake Linux Security Advisory : tetex (MDKSA-2007:164)");
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
"Maurycy Prodeus found an integer overflow vulnerability in the way
various PDF viewers processed PDF files. An attacker could create a
malicious PDF file that could cause tetex to crash and possibly
execute arbitrary code open a user opening the file.

In addition, tetex contains an embedded copy of the GD library which
suffers from a number of bugs which potentially lead to denial of
service and possibly other issues.

Integer overflow in gdImageCreateTrueColor function in the GD Graphics
Library (libgd) before 2.0.35 allows user-assisted remote attackers to
have unspecified remote attack vectors and impact. (CVE-2007-3472)

The gdImageCreateXbm function in the GD Graphics Library (libgd)
before 2.0.35 allows user-assisted remote attackers to cause a denial
of service (crash) via unspecified vectors involving a gdImageCreate
failure. (CVE-2007-3473)

Multiple unspecified vulnerabilities in the GIF reader in the GD
Graphics Library (libgd) before 2.0.35 allow user-assisted remote
attackers to have unspecified attack vectors and impact.
(CVE-2007-3474)

The GD Graphics Library (libgd) before 2.0.35 allows user-assisted
remote attackers to cause a denial of service (crash) via a GIF image
that has no global color map. (CVE-2007-3475)

Array index error in gd_gif_in.c in the GD Graphics Library (libgd)
before 2.0.35 allows user-assisted remote attackers to cause a denial
of service (crash and heap corruption) via large color index values in
crafted image data, which results in a segmentation fault.
(CVE-2007-3476)

The (a) imagearc and (b) imagefilledarc functions in GD Graphics
Library (libgd) before 2.0.35 allows attackers to cause a denial of
service (CPU consumption) via a large (1) start or (2) end angle
degree value. (CVE-2007-3477)

Race condition in gdImageStringFTEx (gdft_draw_bitmap) in gdft.c in
the GD Graphics Library (libgd) before 2.0.35 allows user-assisted
remote attackers to cause a denial of service (crash) via unspecified
vectors, possibly involving truetype font (TTF) support.
(CVE-2007-3478)

Updated packages have been patched to prevent these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(189, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:jadetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-afm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-context");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-dvilj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-dvipdfm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-dvips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-mfwin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-texi2html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-usrlocal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-xdvi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xmltex");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2007.0", reference:"jadetex-3.12-116.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"tetex-3.0-18.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"tetex-afm-3.0-18.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"tetex-context-3.0-18.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"tetex-devel-3.0-18.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"tetex-doc-3.0-18.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"tetex-dvilj-3.0-18.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"tetex-dvipdfm-3.0-18.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"tetex-dvips-3.0-18.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"tetex-latex-3.0-18.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"tetex-mfwin-3.0-18.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"tetex-texi2html-3.0-18.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"tetex-xdvi-3.0-18.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"xmltex-1.9-64.4mdv2007.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2007.1", reference:"jadetex-3.12-129.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"tetex-3.0-31.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"tetex-afm-3.0-31.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"tetex-context-3.0-31.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"tetex-devel-3.0-31.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"tetex-doc-3.0-31.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"tetex-dvilj-3.0-31.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"tetex-dvipdfm-3.0-31.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"tetex-dvips-3.0-31.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"tetex-latex-3.0-31.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"tetex-mfwin-3.0-31.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"tetex-texi2html-3.0-31.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"tetex-usrlocal-3.0-31.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"tetex-xdvi-3.0-31.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"xmltex-1.9-77.3mdv2007.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
