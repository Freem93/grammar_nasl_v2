#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2008:188. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(36926);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/28 21:39:22 $");

  script_cve_id("CVE-2007-5342", "CVE-2008-1232", "CVE-2008-1947", "CVE-2008-2370", "CVE-2008-2938");
  script_xref(name:"MDVSA", value:"2008:188");

  script_name(english:"Mandriva Linux Security Advisory : tomcat5 (MDVSA-2008:188)");
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
"A number of vulnerabilities have been discovered in the Apache Tomcat
server :

The default catalina.policy in the JULI logging component did not
restrict certain permissions for web applications which could allow a
remote attacker to modify logging configuration options and overwrite
arbitrary files (CVE-2007-5342).

A cross-site scripting vulnerability was found in the
HttpServletResponse.sendError() method which could allow a remote
attacker to inject arbitrary web script or HTML via forged HTTP
headers (CVE-2008-1232).

A cross-site scripting vulnerability was found in the host manager
application that could allow a remote attacker to inject arbitrary web
script or HTML via the hostname parameter (CVE-2008-1947).

A traversal vulnerability was found when using a RequestDispatcher in
combination with a servlet or JSP that could allow a remote attacker
to utilize a specially crafted request parameter to access protected
web resources (CVE-2008-2370).

A traversal vulnerability was found when the 'allowLinking' and
'URIencoding' settings were actived which could allow a remote
attacker to use a UTF-8-encoded request to extend their privileges and
obtain local files accessible to the Tomcat process (CVE-2008-2938).

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Tomcat File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(22, 79, 264);

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
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
if (rpm_check(release:"MDK2008.0", reference:"tomcat5-5.5.23-9.2.10.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"tomcat5-admin-webapps-5.5.23-9.2.10.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"tomcat5-common-lib-5.5.23-9.2.10.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"tomcat5-jasper-5.5.23-9.2.10.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"tomcat5-jasper-javadoc-5.5.23-9.2.10.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"tomcat5-jsp-2.0-api-5.5.23-9.2.10.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"tomcat5-jsp-2.0-api-javadoc-5.5.23-9.2.10.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"tomcat5-server-lib-5.5.23-9.2.10.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"tomcat5-servlet-2.4-api-5.5.23-9.2.10.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"tomcat5-servlet-2.4-api-javadoc-5.5.23-9.2.10.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"tomcat5-webapps-5.5.23-9.2.10.2mdv2008.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2008.1", reference:"tomcat5-5.5.25-1.2.1.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"tomcat5-admin-webapps-5.5.25-1.2.1.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"tomcat5-common-lib-5.5.25-1.2.1.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"tomcat5-jasper-5.5.25-1.2.1.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"tomcat5-jasper-eclipse-5.5.25-1.2.1.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"tomcat5-jasper-javadoc-5.5.25-1.2.1.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"tomcat5-jsp-2.0-api-5.5.25-1.2.1.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"tomcat5-jsp-2.0-api-javadoc-5.5.25-1.2.1.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"tomcat5-server-lib-5.5.25-1.2.1.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"tomcat5-servlet-2.4-api-5.5.25-1.2.1.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"tomcat5-servlet-2.4-api-javadoc-5.5.25-1.2.1.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"tomcat5-webapps-5.5.25-1.2.1.1mdv2008.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
