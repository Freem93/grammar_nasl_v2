#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2842. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71933);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/05 14:58:43 $");

  script_cve_id("CVE-2013-4152");
  script_bugtraq_id(61951);
  script_osvdb_id(96520, 102475);
  script_xref(name:"DSA", value:"2842");

  script_name(english:"Debian DSA-2842-1 : libspring-java - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Alvaro Munoz discovered a XML External Entity (XXE) injection in the
Spring Framework which can be used for conducting CSRF and DoS attacks
on other sites.

The Spring OXM wrapper did not expose any property for disabling
entity resolution when using the JAXB unmarshaller. There are four
possible source implementations passed to the unmarshaller :

  - DOMSource
  - StAXSource

  - SAXSource

  - StreamSource

For a DOMSource, the XML has already been parsed by user code and that
code is responsible for protecting against XXE.


For a StAXSource, the XMLStreamReader has already been created by user
code and that code is responsible for protecting against XXE.

For SAXSource and StreamSource instances, Spring processed external
entities by default thereby creating this vulnerability.

The issue was resolved by disabling external entity processing by
default and adding an option to enable it for those users that need to
use this feature when processing XML from a trusted source.

It was also identified that Spring MVC processed user provided XML
with JAXB in combination with a StAX XMLInputFactory without disabling
external entity resolution. External entity resolution has been
disabled in this case."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=720902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libspring-java"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2842"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libspring-java packages.

For the stable distribution (wheezy), this problem has been fixed in
version 3.0.6.RELEASE-6+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libspring-aop-java", reference:"3.0.6.RELEASE-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-beans-java", reference:"3.0.6.RELEASE-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-context-java", reference:"3.0.6.RELEASE-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-context-support-java", reference:"3.0.6.RELEASE-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-core-java", reference:"3.0.6.RELEASE-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-expression-java", reference:"3.0.6.RELEASE-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-instrument-java", reference:"3.0.6.RELEASE-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-jdbc-java", reference:"3.0.6.RELEASE-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-jms-java", reference:"3.0.6.RELEASE-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-orm-java", reference:"3.0.6.RELEASE-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-oxm-java", reference:"3.0.6.RELEASE-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-test-java", reference:"3.0.6.RELEASE-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-transaction-java", reference:"3.0.6.RELEASE-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-web-java", reference:"3.0.6.RELEASE-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-web-portlet-java", reference:"3.0.6.RELEASE-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-web-servlet-java", reference:"3.0.6.RELEASE-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libspring-web-struts-java", reference:"3.0.6.RELEASE-6+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
