#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:177. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(49207);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/28 21:52:55 $");

  script_cve_id("CVE-2009-2693", "CVE-2009-2901", "CVE-2009-2902", "CVE-2010-1157", "CVE-2010-2227");
  script_bugtraq_id(37942, 37945, 39635, 41544);
  script_xref(name:"MDVSA", value:"2010:177");

  script_name(english:"Mandriva Linux Security Advisory : tomcat5 (MDVSA-2010:177)");
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
"Multiple vulnerabilities has been found and corrected in tomcat5 :

Directory traversal vulnerability in Apache Tomcat 5.5.0 through
5.5.28 and 6.0.0 through 6.0.20 allows remote attackers to create or
overwrite arbitrary files via a .. (dot dot) in an entry in a WAR
file, as demonstrated by a ../../bin/catalina.bat entry
(CVE-2009-2693).

The autodeployment process in Apache Tomcat 5.5.0 through 5.5.28 and
6.0.0 through 6.0.20, when autoDeploy is enabled, deploys appBase
files that remain from a failed undeploy, which might allow remote
attackers to bypass intended authentication requirements via HTTP
requests (CVE-2009-2901).

Directory traversal vulnerability in Apache Tomcat 5.5.0 through
5.5.28 and 6.0.0 through 6.0.20 allows remote attackers to delete
work-directory files via directory traversal sequences in a WAR
filename, as demonstrated by the ...war filename (CVE-2009-2902).

Apache Tomcat 5.5.0 through 5.5.29 and 6.0.0 through 6.0.26 might
allow remote attackers to discover the server's hostname or IP address
by sending a request for a resource that requires (1) BASIC or (2)
DIGEST authentication, and then reading the realm field in the
WWW-Authenticate header in the reply (CVE-2010-1157).

Apache Tomcat 5.5.0 through 5.5.29, 6.0.0 through 6.0.27, and 7.0.0
beta does not properly handle an invalid Transfer-Encoding header,
which allows remote attackers to cause a denial of service
(application outage) or obtain sensitive information via a crafted
header that interferes with recycling of a buffer. (CVE-2010-2227)

Packages for 2009.0 are provided as of the Extended Maintenance
Program. Please visit this link to learn more:
http://store.mandriva.com/product_info.php?cPath=149&amp;products_id=4
90

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat5-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat5-common-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat5-jasper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat5-jasper-eclipse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat5-jasper-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat5-jsp-2.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat5-jsp-2.0-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat5-server-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat5-servlet-2.4-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat5-servlet-2.4-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat5-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/13");
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
if (rpm_check(release:"MDK2009.0", reference:"tomcat5-5.5.27-0.3.0.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tomcat5-admin-webapps-5.5.27-0.3.0.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tomcat5-common-lib-5.5.27-0.3.0.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tomcat5-jasper-5.5.27-0.3.0.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tomcat5-jasper-eclipse-5.5.27-0.3.0.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tomcat5-jasper-javadoc-5.5.27-0.3.0.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tomcat5-jsp-2.0-api-5.5.27-0.3.0.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tomcat5-jsp-2.0-api-javadoc-5.5.27-0.3.0.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tomcat5-server-lib-5.5.27-0.3.0.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tomcat5-servlet-2.4-api-5.5.27-0.3.0.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tomcat5-servlet-2.4-api-javadoc-5.5.27-0.3.0.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tomcat5-webapps-5.5.27-0.3.0.3mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.1", reference:"tomcat5-5.5.27-0.3.0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"tomcat5-admin-webapps-5.5.27-0.3.0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"tomcat5-common-lib-5.5.27-0.3.0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"tomcat5-jasper-5.5.27-0.3.0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"tomcat5-jasper-eclipse-5.5.27-0.3.0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"tomcat5-jasper-javadoc-5.5.27-0.3.0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"tomcat5-jsp-2.0-api-5.5.27-0.3.0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"tomcat5-jsp-2.0-api-javadoc-5.5.27-0.3.0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"tomcat5-server-lib-5.5.27-0.3.0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"tomcat5-servlet-2.4-api-5.5.27-0.3.0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"tomcat5-servlet-2.4-api-javadoc-5.5.27-0.3.0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"tomcat5-webapps-5.5.27-0.3.0.2mdv2009.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.0", reference:"tomcat5-5.5.27-0.5.0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"tomcat5-admin-webapps-5.5.27-0.5.0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"tomcat5-common-lib-5.5.27-0.5.0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"tomcat5-jasper-5.5.27-0.5.0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"tomcat5-jasper-eclipse-5.5.27-0.5.0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"tomcat5-jasper-javadoc-5.5.27-0.5.0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"tomcat5-jsp-2.0-api-5.5.27-0.5.0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"tomcat5-jsp-2.0-api-javadoc-5.5.27-0.5.0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"tomcat5-server-lib-5.5.27-0.5.0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"tomcat5-servlet-2.4-api-5.5.27-0.5.0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"tomcat5-servlet-2.4-api-javadoc-5.5.27-0.5.0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"tomcat5-webapps-5.5.27-0.5.0.1mdv2010.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.1", reference:"tomcat5-5.5.28-0.5.0.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"tomcat5-admin-webapps-5.5.28-0.5.0.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"tomcat5-common-lib-5.5.28-0.5.0.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"tomcat5-jasper-5.5.28-0.5.0.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"tomcat5-jasper-eclipse-5.5.28-0.5.0.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"tomcat5-jasper-javadoc-5.5.28-0.5.0.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"tomcat5-jsp-2.0-api-5.5.28-0.5.0.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"tomcat5-jsp-2.0-api-javadoc-5.5.28-0.5.0.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"tomcat5-server-lib-5.5.28-0.5.0.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"tomcat5-servlet-2.4-api-5.5.28-0.5.0.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"tomcat5-servlet-2.4-api-javadoc-5.5.28-0.5.0.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"tomcat5-webapps-5.5.28-0.5.0.1mdv2010.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
