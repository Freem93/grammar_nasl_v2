#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:110. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(46744);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/17 17:02:54 $");

  script_cve_id("CVE-2010-1639", "CVE-2010-1640");
  script_bugtraq_id(40317, 40318);
  script_xref(name:"MDVSA", value:"2010:110");

  script_name(english:"Mandriva Linux Security Advisory : clamav (MDVSA-2010:110)");
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
"Multiple vulnerabilities was discovered and fixed in clamav :

The cli_pdf function in libclamav/pdf.c in ClamAV before 0.96.1 allows
remote attackers to cause a denial of service (crash) via a malformed
PDF file, related to an inconsistency in the calculated stream length
and the real stream length (CVE-2010-1639).

Off-by-one error in the parseicon function in libclamav/pe_icons.c in
ClamAV 0.96 allows remote attackers to cause a denial of service
(crash) via a crafted PE icon that triggers an out-of-bounds read,
related to improper rounding during scaling (CVE-2010-1640).

Packages for 2008.0 and 2009.0 are provided as of the Extended
Maintenance Program. Please visit this link to learn more:
http://store.mandriva.com/product_info.php?cPath=149&amp;products_id=4
90

This update provides clamav 0.96.1 which is not vulnerable to these
issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:clamav-db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:clamav-milter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:clamd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64clamav-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64clamav6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libclamav-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libclamav6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/28");
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
if (rpm_check(release:"MDK2008.0", reference:"clamav-0.96.1-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"clamav-db-0.96.1-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"clamav-milter-0.96.1-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"clamd-0.96.1-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64clamav-devel-0.96.1-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64clamav6-0.96.1-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libclamav-devel-0.96.1-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libclamav6-0.96.1-0.1mdv2008.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.0", reference:"clamav-0.96.1-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"clamav-db-0.96.1-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"clamav-milter-0.96.1-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"clamd-0.96.1-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64clamav-devel-0.96.1-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64clamav6-0.96.1-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libclamav-devel-0.96.1-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libclamav6-0.96.1-0.1mdv2009.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
