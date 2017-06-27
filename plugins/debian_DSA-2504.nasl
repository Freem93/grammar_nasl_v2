#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2504. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59782);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:37:38 $");

  script_cve_id("CVE-2011-2730");
  script_bugtraq_id(49543);
  script_osvdb_id(75264);
  script_xref(name:"DSA", value:"2504");

  script_name(english:"Debian DSA-2504-1 : libspring-2.5-java - information disclosure");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the Spring Framework contains an information
disclosure vulnerability in the processing of certain Expression
Language (EL) patterns, allowing attackers to access sensitive
information using HTTP requests.

NOTE: This update adds a springJspExpressionSupport context parameter
which must be manually set to false when the Spring Framework runs
under a container which provides EL support itself."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=677814"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/libspring-2.5-java"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2504"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libspring-2.5-java packages.

For the stable distribution (squeeze), this problem has been fixed in
version 2.5.6.SEC02-2+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-2.5-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libspring-aop-2.5-java", reference:"2.5.6.SEC02-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libspring-aspects-2.5-java", reference:"2.5.6.SEC02-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libspring-beans-2.5-java", reference:"2.5.6.SEC02-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libspring-context-2.5-java", reference:"2.5.6.SEC02-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libspring-context-support-2.5-java", reference:"2.5.6.SEC02-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libspring-core-2.5-java", reference:"2.5.6.SEC02-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libspring-jdbc-2.5-java", reference:"2.5.6.SEC02-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libspring-jms-2.5-java", reference:"2.5.6.SEC02-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libspring-orm-2.5-java", reference:"2.5.6.SEC02-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libspring-test-2.5-java", reference:"2.5.6.SEC02-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libspring-tx-2.5-java", reference:"2.5.6.SEC02-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libspring-web-2.5-java", reference:"2.5.6.SEC02-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libspring-webmvc-2.5-java", reference:"2.5.6.SEC02-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libspring-webmvc-portlet-2.5-java", reference:"2.5.6.SEC02-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libspring-webmvc-struts-2.5-java", reference:"2.5.6.SEC02-2+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
