#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:121. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(38865);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/28 21:39:23 $");

  script_cve_id("CVE-2009-0581", "CVE-2009-0723", "CVE-2009-0733", "CVE-2009-0793");
  script_bugtraq_id(34185, 34411);
  script_xref(name:"MDVSA", value:"2009:121-1");

  script_name(english:"Mandriva Linux Security Advisory : lcms (MDVSA-2009:121-1)");
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
"Multiple security vulnerabilities has been identified and fixed in
Little cms :

A memory leak flaw allows remote attackers to cause a denial of
service (memory consumption and application crash) via a crafted image
file (CVE-2009-0581).

Multiple integer overflows allow remote attackers to execute arbitrary
code via a crafted image file that triggers a heap-based buffer
overflow (CVE-2009-0723).

Multiple stack-based buffer overflows allow remote attackers to
execute arbitrary code via a crafted image file associated with a
large integer value for the (1) input or (2) output channel
(CVE-2009-0733).

A flaw in the transformations of monochrome profiles allows remote
attackers to cause denial of service triggered by a NULL pointer
dereference via a crafted image file (CVE-2009-0793).

This update provides fixes for these issues.

Update :

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lcms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64lcms-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64lcms1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:liblcms-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:liblcms1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-lcms");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.0", reference:"lcms-1.18-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64lcms-devel-1.18-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64lcms1-1.18-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"liblcms-devel-1.18-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"liblcms1-1.18-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"python-lcms-1.18-0.1mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
