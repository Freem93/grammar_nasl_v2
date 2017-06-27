#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:207. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(50076);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/12/03 12:08:28 $");

  script_cve_id("CVE-2010-3847");
  script_bugtraq_id(44154);
  script_xref(name:"MDVSA", value:"2010:207");

  script_name(english:"Mandriva Linux Security Advisory : glibc (MDVSA-2010:207)");
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
"A vulnerability in the GNU C library (glibc) was discovered which
could escalate the privilegies for local users (CVE-2010-3847).

Packages for 2009.0 are provided as of the Extended Maintenance
Program. Please visit this link to learn more:
http://store.mandriva.com/product_info.php?cPath=149&amp;products_id=4
90

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-i18ndata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/21");
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
if (rpm_check(release:"MDK2009.0", reference:"glibc-2.8-1.20080520.5.6mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"glibc-devel-2.8-1.20080520.5.6mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"glibc-doc-2.8-1.20080520.5.6mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"glibc-doc-pdf-2.8-1.20080520.5.6mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"glibc-i18ndata-2.8-1.20080520.5.6mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"glibc-profile-2.8-1.20080520.5.6mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"glibc-static-devel-2.8-1.20080520.5.6mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"glibc-utils-2.8-1.20080520.5.6mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"nscd-2.8-1.20080520.5.6mnb2")) flag++;

if (rpm_check(release:"MDK2009.1", reference:"glibc-2.9-0.20081113.5.2mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"glibc-devel-2.9-0.20081113.5.2mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"glibc-doc-2.9-0.20081113.5.2mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"glibc-doc-pdf-2.9-0.20081113.5.2mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"glibc-i18ndata-2.9-0.20081113.5.2mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"glibc-profile-2.9-0.20081113.5.2mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"glibc-static-devel-2.9-0.20081113.5.2mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"glibc-utils-2.9-0.20081113.5.2mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nscd-2.9-0.20081113.5.2mnb2")) flag++;

if (rpm_check(release:"MDK2010.0", reference:"glibc-2.10.1-6.6mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"glibc-devel-2.10.1-6.6mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"glibc-doc-2.10.1-6.6mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"glibc-doc-pdf-2.10.1-6.6mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"glibc-i18ndata-2.10.1-6.6mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"glibc-profile-2.10.1-6.6mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"glibc-static-devel-2.10.1-6.6mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"glibc-utils-2.10.1-6.6mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"nscd-2.10.1-6.6mnb2")) flag++;

if (rpm_check(release:"MDK2010.1", reference:"glibc-2.11.1-8.1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"glibc-devel-2.11.1-8.1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"glibc-doc-2.11.1-8.1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"glibc-doc-pdf-2.11.1-8.1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"glibc-i18ndata-2.11.1-8.1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"glibc-profile-2.11.1-8.1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"glibc-static-devel-2.11.1-8.1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"glibc-utils-2.11.1-8.1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"nscd-2.11.1-8.1mnb2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");