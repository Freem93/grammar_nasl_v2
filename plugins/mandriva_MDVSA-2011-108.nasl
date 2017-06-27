#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2011:108. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(55111);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2013/06/01 00:15:52 $");

  script_cve_id("CVE-2009-2625");
  script_bugtraq_id(35958);
  script_xref(name:"MDVSA", value:"2011:108");

  script_name(english:"Mandriva Linux Security Advisory : xerces-j2 (MDVSA-2011:108)");
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
"A vulnerability was discovered and corrected in xerces-j2 :

Apache Xerces2 Java, as used in Sun Java Runtime Environment (JRE) in
JDK and JRE 6 before Update 15 and JDK and JRE 5.0 before Update 20,
and in other products, allows remote attackers to cause a denial of
service (infinite loop and application hang) via malformed XML input,
as demonstrated by the Codenomicon XML fuzzing framework
(CVE-2009-2625).

Packages for 2009.0 are provided as of the Extended Maintenance
Program. Please visit this link to learn more:
http://store.mandriva.com/product_info.php?cPath=149 products_id=490

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xerces-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xerces-j2-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xerces-j2-javadoc-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xerces-j2-javadoc-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xerces-j2-javadoc-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xerces-j2-javadoc-xni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xerces-j2-scripts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/14");
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
if (rpm_check(release:"MDK2009.0", reference:"xerces-j2-2.9.0-9.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"xerces-j2-demo-2.9.0-9.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"xerces-j2-javadoc-apis-2.9.0-9.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"xerces-j2-javadoc-impl-2.9.0-9.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"xerces-j2-javadoc-other-2.9.0-9.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"xerces-j2-javadoc-xni-2.9.0-9.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"xerces-j2-scripts-2.9.0-9.1mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.1", reference:"xerces-j2-2.9.0-12.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"xerces-j2-demo-2.9.0-12.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"xerces-j2-javadoc-apis-2.9.0-12.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"xerces-j2-javadoc-impl-2.9.0-12.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"xerces-j2-javadoc-other-2.9.0-12.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"xerces-j2-javadoc-xni-2.9.0-12.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"xerces-j2-scripts-2.9.0-12.1mdv2010.2", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
