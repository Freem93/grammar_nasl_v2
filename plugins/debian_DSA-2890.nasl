#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2890. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73255);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:43:11 $");

  script_cve_id("CVE-2014-0054", "CVE-2014-1904");
  script_bugtraq_id(66137, 66148);
  script_xref(name:"DSA", value:"2890");

  script_name(english:"Debian DSA-2890-1 : libspring-java - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities were discovered in libspring-java, the Debian
package for the Java Spring framework.

  - CVE-2014-0054
    Jaxb2RootElementHttpMessageConverter in Spring MVC
    processes external XML entities.

  - CVE-2014-1904
    Spring MVC introduces a cross-site scripting
    vulnerability if the action on a Spring form is not
    specified."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=741604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-1904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libspring-java"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2890"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libspring-java packages.

For the stable distribution (wheezy), these problems have been fixed
in version 3.0.6.RELEASE-6+deb7u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libspring-aop-java", reference:"3.0.6.RELEASE-6+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-beans-java", reference:"3.0.6.RELEASE-6+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-context-java", reference:"3.0.6.RELEASE-6+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-context-support-java", reference:"3.0.6.RELEASE-6+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-core-java", reference:"3.0.6.RELEASE-6+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-expression-java", reference:"3.0.6.RELEASE-6+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-instrument-java", reference:"3.0.6.RELEASE-6+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-jdbc-java", reference:"3.0.6.RELEASE-6+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-jms-java", reference:"3.0.6.RELEASE-6+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-orm-java", reference:"3.0.6.RELEASE-6+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-oxm-java", reference:"3.0.6.RELEASE-6+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-test-java", reference:"3.0.6.RELEASE-6+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-transaction-java", reference:"3.0.6.RELEASE-6+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-web-java", reference:"3.0.6.RELEASE-6+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-web-portlet-java", reference:"3.0.6.RELEASE-6+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-web-servlet-java", reference:"3.0.6.RELEASE-6+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-web-struts-java", reference:"3.0.6.RELEASE-6+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
