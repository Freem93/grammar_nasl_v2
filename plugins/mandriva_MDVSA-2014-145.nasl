#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:145. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(76952);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/19 15:01:01 $");

  script_cve_id("CVE-2014-4914");
  script_bugtraq_id(68031);
  script_xref(name:"MDVSA", value:"2014:145");

  script_name(english:"Mandriva Linux Security Advisory : php-ZendFramework (MDVSA-2014:145)");
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
"A vulnerability has been found and corrected in php-ZendFramework :

The implementation of the ORDER BY SQL statement in Zend_Db_Select of
Zend Framework 1 contains a potential SQL injection when the query
string passed contains parentheses (CVE-2014-4914).

The updated packages have been upgraded to the latest ZendFramework
(1.12.7) version which is not vulnerable to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://framework.zend.com/security/advisory/ZF2014-04"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ZendFramework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ZendFramework-Cache-Backend-Apc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ZendFramework-Cache-Backend-Memcached");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ZendFramework-Captcha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ZendFramework-Dojo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ZendFramework-Feed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ZendFramework-Gdata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ZendFramework-Pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ZendFramework-Search-Lucene");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ZendFramework-Services");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ZendFramework-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ZendFramework-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ZendFramework-tests");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", reference:"php-ZendFramework-1.12.7-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"php-ZendFramework-Cache-Backend-Apc-1.12.7-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"php-ZendFramework-Cache-Backend-Memcached-1.12.7-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"php-ZendFramework-Captcha-1.12.7-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"php-ZendFramework-Dojo-1.12.7-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"php-ZendFramework-Feed-1.12.7-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"php-ZendFramework-Gdata-1.12.7-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"php-ZendFramework-Pdf-1.12.7-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"php-ZendFramework-Search-Lucene-1.12.7-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"php-ZendFramework-Services-1.12.7-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"php-ZendFramework-demos-1.12.7-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"php-ZendFramework-extras-1.12.7-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"php-ZendFramework-tests-1.12.7-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
