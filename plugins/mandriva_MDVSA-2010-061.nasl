#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:061. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(45041);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/28 21:39:24 $");

  script_cve_id("CVE-2010-0790", "CVE-2010-0791");
  script_xref(name:"MDVSA", value:"2010:061");

  script_name(english:"Mandriva Linux Security Advisory : ncpfs (MDVSA-2010:061)");
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
"Multiple vulnerabilities has been found and corrected in ncpfs :

sutil/ncpumount.c in ncpumount in ncpfs 2.2.6 produces certain
detailed error messages about the results of privileged file-access
attempts, which allows local users to determine the existence of
arbitrary files via the mountpoint name (CVE-2010-0790).

The (1) ncpmount, (2) ncpumount, and (3) ncplogin programs in ncpfs
2.2.6 do not properly create lock files, which allows local users to
cause a denial of service (application failure) via unspecified
vectors that trigger the creation of a /etc/mtab~ file that persists
after the program exits (CVE-2010-0791).

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers.

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ipxutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ncpfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ncpfs2.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ncpfs2.3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libncpfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libncpfs2.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libncpfs2.3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ncpfs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.0", reference:"ipxutils-2.2.6-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64ncpfs2.3-2.2.6-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64ncpfs2.3-devel-2.2.6-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libncpfs2.3-2.2.6-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libncpfs2.3-devel-2.2.6-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ncpfs-2.2.6-3.2mdv2008.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.0", reference:"ipxutils-2.2.6-6.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64ncpfs-devel-2.2.6-6.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64ncpfs2.3-2.2.6-6.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libncpfs-devel-2.2.6-6.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libncpfs2.3-2.2.6-6.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"ncpfs-2.2.6-6.2mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.1", reference:"ipxutils-2.2.6-7.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64ncpfs-devel-2.2.6-7.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64ncpfs2.3-2.2.6-7.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libncpfs-devel-2.2.6-7.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libncpfs2.3-2.2.6-7.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"ncpfs-2.2.6-7.2mdv2009.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.0", reference:"ipxutils-2.2.6-7.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64ncpfs-devel-2.2.6-7.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64ncpfs2.3-2.2.6-7.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libncpfs-devel-2.2.6-7.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libncpfs2.3-2.2.6-7.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"ncpfs-2.2.6-7.2mdv2010.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
