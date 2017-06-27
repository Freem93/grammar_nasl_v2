#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1453. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29872);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-3382", "CVE-2007-3385", "CVE-2007-5461");
  script_osvdb_id(37070, 37071, 38187);
  script_xref(name:"DSA", value:"1453");

  script_name(english:"Debian DSA-1453-1 : tomcat5 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in the Tomcat
servlet and JSP engine. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2007-3382
    It was discovered that single quotes (') in cookies were
    treated as a delimiter, which could lead to an
    information leak.

  - CVE-2007-3385
    It was discovered that the character sequence \' in
    cookies was handled incorrectly, which could lead to an
    information leak.

  - CVE-2007-5461
    It was discovered that the WebDAV servlet is vulnerable
    to absolute path traversal."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3385"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1453"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the tomcat5 packages.

The old stable distribution (sarge) doesn't contain tomcat5.

For the stable distribution (etch), these problems have been fixed in
version 5.0.30-12etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cwe_id(22, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/08");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libtomcat5-java", reference:"5.0.30-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"tomcat5", reference:"5.0.30-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"tomcat5-admin", reference:"5.0.30-12etch1")) flag++;
if (deb_check(release:"4.0", prefix:"tomcat5-webapps", reference:"5.0.30-12etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
