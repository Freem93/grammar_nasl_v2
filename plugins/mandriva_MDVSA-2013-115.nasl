#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:115. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(66127);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/17 17:13:09 $");

  script_cve_id("CVE-2012-5657");
  script_bugtraq_id(56982);
  script_xref(name:"MDVSA", value:"2013:115");
  script_xref(name:"MGASA", value:"2012-0367");

  script_name(english:"Mandriva Linux Security Advisory : php-ZendFramework (MDVSA-2013:115)");
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
"Updated php-ZendFramework packages fix security vulnerabilities :

Zend_Dom, Zend_Feed, Zend_Soap, and Zend_XmlRpc in Zend Framework
before 1.11.13 and 1.12.0 are vulnerable to XML Entity Expansion (XEE)
vectors, leading to Denial of Service vectors. XEE attacks occur when
the XML DOCTYPE declaration includes XML entity definitions that
contain either recursive or circular references; this leads to CPU and
memory consumption, making Denial of Service exploits trivial to
implement (ZF2012-02).

A vulnerability was reported in Zend Framework versions prior to
1.11.15 and 1.12.1, which can be exploited to disclose certain
sensitive information. This flaw is caused due to an error in the
Zend_Feed_Rss and Zend_Feed_Atom classes of the Zend_Feed component,
when processing XML data. It can be used to disclose the contents of
certain local files by sending specially crafted XML data including
external entity references (CVE-2012-5657, ZF2012-05)."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", reference:"php-ZendFramework-1.12.1-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"php-ZendFramework-Cache-Backend-Apc-1.12.1-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"php-ZendFramework-Cache-Backend-Memcached-1.12.1-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"php-ZendFramework-Captcha-1.12.1-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"php-ZendFramework-Dojo-1.12.1-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"php-ZendFramework-Feed-1.12.1-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"php-ZendFramework-Gdata-1.12.1-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"php-ZendFramework-Pdf-1.12.1-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"php-ZendFramework-Search-Lucene-1.12.1-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"php-ZendFramework-Services-1.12.1-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"php-ZendFramework-demos-1.12.1-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"php-ZendFramework-extras-1.12.1-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"php-ZendFramework-tests-1.12.1-1.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
