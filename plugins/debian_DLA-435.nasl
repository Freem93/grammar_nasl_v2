#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-435-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(88996);
  script_version("$Revision: 2.14 $");
  script_cvs_date("$Date: 2016/12/06 20:03:51 $");

  script_cve_id("CVE-2015-5174", "CVE-2015-5345", "CVE-2015-5351", "CVE-2016-0706", "CVE-2016-0714", "CVE-2016-0763");
  script_osvdb_id(134823, 134824, 134825, 134826, 134828, 134829);

  script_name(english:"Debian DLA-435-1 : tomcat6 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tomcat 6, an implementation of the Java Servlet and the JavaServer
Pages (JSP) specifications and a pure Java web server environment, was
affected by multiple security issues prior version 6.0.45.

CVE-2015-5174 Directory traversal vulnerability in RequestUtil.java in
Apache Tomcat 6.x before 6.0.45, 7.x before 7.0.65, and 8.x before
8.0.27 allows remote authenticated users to bypass intended
SecurityManager restrictions and list a parent directory via a /..
(slash dot dot) in a pathname used by a web application in a
getResource, getResourceAsStream, or getResourcePaths call, as
demonstrated by the $CATALINA_BASE/webapps directory.

CVE-2015-5345 The Mapper component in Apache Tomcat 6.x before 6.0.45,
7.x before 7.0.67, 8.x before 8.0.30, and 9.x before 9.0.0.M2
processes redirects before considering security constraints and
Filters, which allows remote attackers to determine the existence of a
directory via a URL that lacks a trailing / (slash) character.

CVE-2015-5351 The Manager and Host Manager applications in Apache
Tomcat establish sessions and send CSRF tokens for arbitrary new
requests, which allows remote attackers to bypass a CSRF protection
mechanism by using a token.

CVE-2016-0706 Apache Tomcat 6.x before 6.0.45, 7.x before 7.0.68, 8.x
before 8.0.31, and 9.x before 9.0.0.M2 does not place
org.apache.catalina.manager.StatusManagerServlet on the org/apache
/catalina/core/RestrictedServlets.properties list, which allows remote
authenticated users to bypass intended SecurityManager restrictions
and read arbitrary HTTP requests, and consequently discover session ID
values, via a crafted web application.

CVE-2016-0714 The session-persistence implementation in Apache Tomcat
6.x before 6.0.45, 7.x before 7.0.68, 8.x before 8.0.31, and 9.x
before 9.0.0.M2 mishandles session attributes, which allows remote
authenticated users to bypass intended SecurityManager restrictions
and execute arbitrary code in a privileged context via a web
application that places a crafted object in a session.

CVE-2016-0763 The setGlobalContext method in org/apache/naming/factory
/ResourceLinkFactory.java in Apache Tomcat does not consider whether
ResourceLinkFactory.setGlobalContext callers are authorized, which
allows remote authenticated users to bypass intended SecurityManager
restrictions and read or write to arbitrary application data, or cause
a denial of service (application disruption), via a web application
that sets a crafted global context.

For Debian 6 'Squeeze', these problems have been fixed in version
6.0.45-1~deb6u1.

We recommend that you upgrade your tomcat6 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/02/msg00027.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/tomcat6"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libservlet2.4-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libservlet2.5-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libservlet2.5-java-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtomcat6-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6-user");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"6.0", prefix:"libservlet2.4-java", reference:"6.0.45-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libservlet2.5-java", reference:"6.0.45-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libservlet2.5-java-doc", reference:"6.0.45-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libtomcat6-java", reference:"6.0.45-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6", reference:"6.0.45-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-admin", reference:"6.0.45-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-common", reference:"6.0.45-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-docs", reference:"6.0.45-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-examples", reference:"6.0.45-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-extras", reference:"6.0.45-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-user", reference:"6.0.45-1~deb6u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
