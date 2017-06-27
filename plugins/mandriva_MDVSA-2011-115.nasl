#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2011:115. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(55634);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/17 17:02:55 $");

  script_cve_id("CVE-2011-2464");
  script_bugtraq_id(48566);
  script_xref(name:"MDVSA", value:"2011:115");

  script_name(english:"Mandriva Linux Security Advisory : bind (MDVSA-2011:115)");
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
"A vulnerability was discovered and corrected in bind :

Unspecified vulnerability in ISC BIND 9 9.6.x before 9.6-ESV-R4-P3,
9.7.x before 9.7.3-P3, and 9.8.x before 9.8.0-P4 allows remote
attackers to cause a denial of service (named daemon crash) via a
crafted UPDATE request (CVE-2011-2464).

Packages for 2009.0 are provided as of the Extended Maintenance
Program. Please visit this link to learn more:
http://store.mandriva.com/product_info.php?cPath=149 products_id=490

The updated packages have been upgraded to bind 9.7.3-P3 which is not
vulnerable to this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:bind-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/21");
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
if (rpm_check(release:"MDK2009.0", reference:"bind-9.7.3-0.0.P3.1.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"bind-devel-9.7.3-0.0.P3.1.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"bind-doc-9.7.3-0.0.P3.1.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"bind-utils-9.7.3-0.0.P3.1.1mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.1", reference:"bind-9.7.3-0.0.P3.1.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"bind-devel-9.7.3-0.0.P3.1.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"bind-doc-9.7.3-0.0.P3.1.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"bind-utils-9.7.3-0.0.P3.1.1mdv2010.2", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
