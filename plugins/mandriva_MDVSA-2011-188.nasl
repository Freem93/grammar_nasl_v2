#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2011:188. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(57320);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/11/14 12:03:06 $");

  script_cve_id("CVE-2011-0216", "CVE-2011-3905");
  script_bugtraq_id(48832);
  script_xref(name:"MDVSA", value:"2011:188");

  script_name(english:"Mandriva Linux Security Advisory : libxml2 (MDVSA-2011:188)");
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
"Multiple vulnerabilities has been discovered and corrected in 
libxml2 :

Off-by-one error in libxml allows remote attackers to execute
arbitrary code or cause a denial of service (heap-based buffer
overflow and application crash) via a crafted website CVE-2011-0216).

libxml2 allows remote attackers to cause a denial of service
(out-of-bounds read) via unspecified vectors (CVE-2011-3905).

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xml2_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxml2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxml2_2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2011");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64xml2-devel-2.7.7-1.5mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64xml2_2-2.7.7-1.5mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libxml2-devel-2.7.7-1.5mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"libxml2-python-2.7.7-1.5mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"libxml2-utils-2.7.7-1.5mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libxml2_2-2.7.7-1.5mdv2010.2", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64xml2-devel-2.7.8-6.3-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64xml2_2-2.7.8-6.3-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libxml2-devel-2.7.8-6.3-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libxml2-python-2.7.8-6.3-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libxml2-utils-2.7.8-6.3-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libxml2_2-2.7.8-6.3-mdv2011.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
