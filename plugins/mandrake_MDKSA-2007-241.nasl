#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:241. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(38147);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/28 21:39:22 $");

  script_cve_id("CVE-2007-0450", "CVE-2007-2449", "CVE-2007-2450", "CVE-2007-3382", "CVE-2007-3385", "CVE-2007-3386", "CVE-2007-5461");
  script_xref(name:"MDKSA", value:"2007:241");

  script_name(english:"Mandrake Linux Security Advisory : tomcat5 (MDKSA-2007:241)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandrake Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A number of vulnerabilities were found in Tomcat :

A directory traversal vulnerability, when using certain proxy modules,
allows a remote attacker to read arbitrary files via a .. (dot dot)
sequence with various slash, backslash, or url-encoded backslash
characters (CVE-2007-0450; affects Mandriva Linux 2007.1 only).

Multiple cross-site scripting vulnerabilities in certain JSP files
allow remote attackers to inject arbitrary web script or HTML
(CVE-2007-2449).

Multiple cross-site scripting vulnerabilities in the Manager and Host
Manager web applications allow remote authenticated users to inject
arbitrary web script or HTML (CVE-2007-2450).

Tomcat treated single quotes as delimiters in cookies, which could
cause sensitive information such as session IDs to be leaked and allow
remote attackers to conduct session hijacking attacks (CVE-2007-3382).

Tomcat did not properly handle the ' character sequence in a cookie
value, which could cause sensitive information such as session IDs to
be leaked and allow remote attackers to conduct session hijacking
attacks (CVE-2007-3385).

A cross-site scripting vulnerability in the Host Manager servlet
allowed remote attackers to inject arbitrary HTML and web script via
crafted attacks (CVE-2007-3386).

Finally, an absolute path traversal vulnerability, under certain
configurations, allows remote authenticated users to read arbitrary
files via a WebDAV write request that specifies an entity with a
SYSTEM tag (CVE-2007-5461).

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(22, 79, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat5-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat5-common-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat5-jasper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat5-jasper-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat5-jsp-2.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat5-jsp-2.0-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat5-server-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat5-servlet-2.4-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat5-servlet-2.4-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat5-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/10");
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
if (rpm_check(release:"MDK2007.1", reference:"tomcat5-5.5.17-6.2.4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"tomcat5-admin-webapps-5.5.17-6.2.4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"tomcat5-common-lib-5.5.17-6.2.4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"tomcat5-jasper-5.5.17-6.2.4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"tomcat5-jasper-javadoc-5.5.17-6.2.4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"tomcat5-jsp-2.0-api-5.5.17-6.2.4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"tomcat5-jsp-2.0-api-javadoc-5.5.17-6.2.4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"tomcat5-server-lib-5.5.17-6.2.4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"tomcat5-servlet-2.4-api-5.5.17-6.2.4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"tomcat5-servlet-2.4-api-javadoc-5.5.17-6.2.4.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"tomcat5-webapps-5.5.17-6.2.4.1mdv2007.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2008.0", reference:"tomcat5-5.5.23-9.2.10.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"tomcat5-admin-webapps-5.5.23-9.2.10.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"tomcat5-common-lib-5.5.23-9.2.10.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"tomcat5-jasper-5.5.23-9.2.10.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"tomcat5-jasper-javadoc-5.5.23-9.2.10.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"tomcat5-jsp-2.0-api-5.5.23-9.2.10.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"tomcat5-jsp-2.0-api-javadoc-5.5.23-9.2.10.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"tomcat5-server-lib-5.5.23-9.2.10.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"tomcat5-servlet-2.4-api-5.5.23-9.2.10.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"tomcat5-servlet-2.4-api-javadoc-5.5.23-9.2.10.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"tomcat5-webapps-5.5.23-9.2.10.1mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
