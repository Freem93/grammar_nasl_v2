#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-594. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15729);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/18 00:11:36 $");

  script_cve_id("CVE-2004-0940");
  script_osvdb_id(10068, 11003, 12881);
  script_xref(name:"DSA", value:"594");

  script_name(english:"Debian DSA-594-1 : apache - buffer overflows");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities have been identified in the Apache 1.3 webserver :

  - CAN-2004-0940
    'Crazy Einstein' has discovered a vulnerability in the
    'mod_include' module, which can cause a buffer to be
    overflown and could lead to the execution of arbitrary
    code.

  - NO VULN ID

    Larry Cashdollar has discovered a potential buffer
    overflow in the htpasswd utility, which could be
    exploited when user-supplied is passed to the program
    via a CGI (or PHP, or ePerl, ...) program."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-594"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the apache packages.

For the stable distribution (woody) these problems have been fixed in
version 1.3.26-0woody6."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/17");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"apache", reference:"1.3.26-0woody6")) flag++;
if (deb_check(release:"3.0", prefix:"apache-common", reference:"1.3.26-0woody6")) flag++;
if (deb_check(release:"3.0", prefix:"apache-dev", reference:"1.3.26-0woody6")) flag++;
if (deb_check(release:"3.0", prefix:"apache-doc", reference:"1.3.26-0woody6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
