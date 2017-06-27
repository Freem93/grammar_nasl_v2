#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:138. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(39486);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/28 21:39:23 $");

  script_cve_id("CVE-2008-5515", "CVE-2009-0033", "CVE-2009-0580", "CVE-2009-0781", "CVE-2009-0783");
  script_bugtraq_id(35193, 35196, 35263, 35416);
  script_xref(name:"MDVSA", value:"2009:138");

  script_name(english:"Mandriva Linux Security Advisory : tomcat5 (MDVSA-2009:138)");
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
tomcat5 :

Apache Tomcat 4.1.0 through 4.1.39, 5.5.0 through 5.5.27, 6.0.0
through 6.0.18, and possibly earlier versions normalizes the target
pathname before filtering the query string when using the
RequestDispatcher method, which allows remote attackers to bypass
intended access restrictions and conduct directory traversal attacks
via .. (dot dot) sequences and the WEB-INF directory in a Request
(CVE-2008-5515).

Apache Tomcat 4.1.0 through 4.1.39, 5.5.0 through 5.5.27, and 6.0.0
through 6.0.18, when the Java AJP connector and mod_jk load balancing
are used, allows remote attackers to cause a denial of service
(application outage) via a crafted request with invalid headers,
related to temporary blocking of connectors that have encountered
errors, as demonstrated by an error involving a malformed HTTP Host
header (CVE-2009-0033).

Apache Tomcat 4.1.0 through 4.1.39, 5.5.0 through 5.5.27, and 6.0.0
through 6.0.18, when FORM authentication is used, allows remote
attackers to enumerate valid usernames via requests to
/j_security_check with malformed URL encoding of passwords, related to
improper error checking in the (1) MemoryRealm, (2) DataSourceRealm,
and (3) JDBCRealm authentication realms, as demonstrated by a %
(percent) value for the j_password parameter (CVE-2009-0580).

The calendar application in the examples web application contains an
XSS flaw due to invalid HTML which renders the XSS filtering
protection ineffective (CVE-2009-0781).

Apache Tomcat 4.1.0 through 4.1.39, 5.5.0 through 5.5.27, and 6.0.0
through 6.0.18 permits web applications to replace an XML parser used
for other web applications, which allows local users to read or modify
the (1) web.xml, (2) context.xml, or (3) tld files of arbitrary web
applications via a crafted application that is loaded earlier than the
target application (CVE-2009-0783).

The updated packages have been patched to prevent this. Additionally
Apache Tomcat has been upgraded to the latest 5.5.27 version for
2009.0."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://tomcat.apache.org/security-5.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20, 22, 79, 200);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/23");
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
if (rpm_check(release:"MDK2009.0", reference:"tomcat5-5.5.27-0.3.0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tomcat5-admin-webapps-5.5.27-0.3.0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tomcat5-common-lib-5.5.27-0.3.0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tomcat5-jasper-5.5.27-0.3.0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tomcat5-jasper-eclipse-5.5.27-0.3.0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tomcat5-jasper-javadoc-5.5.27-0.3.0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tomcat5-jsp-2.0-api-5.5.27-0.3.0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tomcat5-jsp-2.0-api-javadoc-5.5.27-0.3.0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tomcat5-server-lib-5.5.27-0.3.0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tomcat5-servlet-2.4-api-5.5.27-0.3.0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tomcat5-servlet-2.4-api-javadoc-5.5.27-0.3.0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tomcat5-webapps-5.5.27-0.3.0.1mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.1", reference:"tomcat5-5.5.27-0.3.0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"tomcat5-admin-webapps-5.5.27-0.3.0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"tomcat5-common-lib-5.5.27-0.3.0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"tomcat5-jasper-5.5.27-0.3.0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"tomcat5-jasper-eclipse-5.5.27-0.3.0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"tomcat5-jasper-javadoc-5.5.27-0.3.0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"tomcat5-jsp-2.0-api-5.5.27-0.3.0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"tomcat5-jsp-2.0-api-javadoc-5.5.27-0.3.0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"tomcat5-server-lib-5.5.27-0.3.0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"tomcat5-servlet-2.4-api-5.5.27-0.3.0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"tomcat5-servlet-2.4-api-javadoc-5.5.27-0.3.0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"tomcat5-webapps-5.5.27-0.3.0.1mdv2009.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
