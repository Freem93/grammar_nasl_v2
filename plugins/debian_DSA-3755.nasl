#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3755. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96345);
  script_version("$Revision: 3.5 $");
  script_cvs_date("$Date: 2017/04/15 13:47:37 $");

  script_cve_id("CVE-2016-8745");
  script_osvdb_id(148477);
  script_xref(name:"DSA", value:"3755");

  script_name(english:"Debian DSA-3755-1 : tomcat8 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that incorrect error handling in the NIO HTTP
connector of the Tomcat servlet and JSP engine could result in
information disclosure."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/tomcat8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2017/dsa-3755"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the tomcat8 packages.

For the stable distribution (jessie), this problem has been fixed in
version 8.0.14-1+deb8u6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"libservlet3.1-java", reference:"8.0.14-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libservlet3.1-java-doc", reference:"8.0.14-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libtomcat8-java", reference:"8.0.14-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat8", reference:"8.0.14-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat8-admin", reference:"8.0.14-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat8-common", reference:"8.0.14-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat8-docs", reference:"8.0.14-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat8-examples", reference:"8.0.14-1+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat8-user", reference:"8.0.14-1+deb8u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");