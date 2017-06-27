#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:193. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(49740);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/06/01 00:15:50 $");

  script_cve_id("CVE-2010-3374");
  script_xref(name:"MDVSA", value:"2010:193");

  script_name(english:"Mandriva Linux Security Advisory : qt-creator (MDVSA-2010:193)");
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
"A vulnerability has been found in Qt Creator 2.0.0 and previous
versions. The vulnerability occurs because of an insecure manipulation
of a Unix environment variable by the qtcreator shell script. It
manifests by causing Qt or Qt Creator to attempt to load certain
library names from the current working directory (CVE-2010-3374).

The updated packages have been patched to correct this issue."
  );
  # http://qt.nokia.com/about/news/security-announcement-qt-creator-2.0.0-for-desktop-platforms
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ebd33386"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64aggregation1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64cplusplus1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64extensionsystem1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtconcurrent1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64utils1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libaggregation1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libcplusplus1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libextensionsystem1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtconcurrent1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libutils1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt-creator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt-creator-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/06");
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
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64aggregation1-1.2.1-2.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64cplusplus1-1.2.1-2.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64extensionsystem1-1.2.1-2.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64qtconcurrent1-1.2.1-2.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64utils1-1.2.1-2.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libaggregation1-1.2.1-2.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libcplusplus1-1.2.1-2.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libextensionsystem1-1.2.1-2.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libqtconcurrent1-1.2.1-2.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libutils1-1.2.1-2.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"qt-creator-1.2.1-2.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"qt-creator-doc-1.2.1-2.2mdv2010.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.1", reference:"qt-creator-1.3.1-3.2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"qt-creator-doc-1.3.1-3.2mdv2010.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
