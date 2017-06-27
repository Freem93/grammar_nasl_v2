#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:053. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(81936);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/05/24 04:37:34 $");

  script_cve_id("CVE-2014-0075", "CVE-2014-0096", "CVE-2014-0099", "CVE-2014-0119", "CVE-2014-0227");
  script_bugtraq_id(67667, 67668, 67669, 67671, 72717);
  script_xref(name:"MDVSA", value:"2015:053");

  script_name(english:"Mandriva Linux Security Advisory : tomcat6 (MDVSA-2015:053)");
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
"Updated tomcat6 packages fix security vulnerabilities :

Integer overflow in the parseChunkHeader function in
java/org/apache/coyote/http11/filters/ChunkedInputFilter.java in
Apache Tomcat before 6.0.40 and 7.x before 7.0.53 allows remote
attackers to cause a denial of service (resource consumption) via a
malformed chunk size in chunked transfer coding of a request during
the streaming of data (CVE-2014-0075).

java/org/apache/catalina/servlets/DefaultServlet.java in the default
servlet in Apache Tomcat before 6.0.40 and 7.x before 7.0.53 does not
properly restrict XSLT stylesheets, which allows remote attackers to
bypass security-manager restrictions and read arbitrary files via a
crafted web application that provides an XML external entity
declaration in conjunction with an entity reference, related to an XML
External Entity (XXE) issue (CVE-2014-0096).

Integer overflow in java/org/apache/tomcat/util/buf/Ascii.java in
Apache Tomcat before 6.0.40 and 7.x before 7.0.53, when operated
behind a reverse proxy, allows remote attackers to conduct HTTP
request smuggling attacks via a crafted Content-Length HTTP header
(CVE-2014-0099).

Apache Tomcat before 6.0.40 and 7.x before 7.0.54 does not properly
constrain the class loader that accesses the XML parser used with an
XSLT stylesheet, which allows remote attackers to read arbitrary files
via a crafted web application that provides an XML external entity
declaration in conjunction with an entity reference, related to an XML
External Entity (XXE) issue, or read files associated with different
web applications on a single Tomcat instance via a crafted web
application (CVE-2014-0119).

In Apache Tomcat 6.x before 6.0.55, it was possible to craft a
malformed chunk as part of a chunked request that caused Tomcat to
read part of the request body as a new request (CVE-2014-0227)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0268.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2015-0081.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat6-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat6-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat6-el-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat6-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat6-jsp-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat6-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat6-servlet-2.5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat6-systemv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat6-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", reference:"tomcat6-6.0.43-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"tomcat6-admin-webapps-6.0.43-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"tomcat6-docs-webapp-6.0.43-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"tomcat6-el-2.1-api-6.0.43-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"tomcat6-javadoc-6.0.43-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"tomcat6-jsp-2.1-api-6.0.43-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"tomcat6-lib-6.0.43-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"tomcat6-servlet-2.5-api-6.0.43-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"tomcat6-systemv-6.0.43-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"tomcat6-webapps-6.0.43-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
