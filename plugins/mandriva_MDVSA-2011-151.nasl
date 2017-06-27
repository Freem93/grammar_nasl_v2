#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2011:151. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(56529);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/17 17:02:55 $");

  script_cve_id("CVE-2011-2501", "CVE-2011-2690", "CVE-2011-2691", "CVE-2011-2692");
  script_bugtraq_id(48474, 48618, 48660);
  script_xref(name:"MDVSA", value:"2011:151");

  script_name(english:"Mandriva Linux Security Advisory : libpng (MDVSA-2011:151)");
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
"Multiple vulnerabilities has been discovered and corrected in libpng :

The png_format_buffer function in pngerror.c in libpng allows remote
attackers to cause a denial of service (application crash) via a
crafted PNG image that triggers an out-of-bounds read during the
copying of error-message data. NOTE: this vulnerability exists because
of a CVE-2004-0421 regression (CVE-2011-2501).

Buffer overflow in libpng, when used by an application that calls the
png_rgb_to_gray function but not the png_set_expand function, allows
remote attackers to overwrite memory with an arbitrary amount of data,
and possibly have unspecified other impact, via a crafted PNG image
(CVE-2011-2690).

The png_err function in pngerror.c in libpng makes a function call
using a NULL pointer argument instead of an empty-string argument,
which allows remote attackers to cause a denial of service
(application crash) via a crafted PNG image (CVE-2011-2691). NOTE:
This does not affect the binary packages in Mandriva, but could affect
users if PNG_NO_ERROR_TEXT is defined using the libpng-source-1.?.??
package.

The png_handle_sCAL function in pngrutil.c in libpng does not properly
handle invalid sCAL chunks, which allows remote attackers to cause a
denial of service (memory corruption and application crash) or
possibly have unspecified other impact via a crafted PNG image that
triggers the reading of uninitialized memory (CVE-2011-2692).

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64png-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64png-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64png3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpng-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpng-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpng-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpng3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64png-devel-1.2.43-1.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64png-static-devel-1.2.43-1.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64png3-1.2.43-1.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libpng-devel-1.2.43-1.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"libpng-source-1.2.43-1.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libpng-static-devel-1.2.43-1.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libpng3-1.2.43-1.2mdv2010.2", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
