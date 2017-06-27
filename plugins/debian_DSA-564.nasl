#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-564. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15662);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/18 00:11:36 $");

  script_cve_id("CVE-2004-0805");
  script_osvdb_id(9748);
  script_xref(name:"DSA", value:"564");

  script_name(english:"Debian DSA-564-1 : mpg123 - missing user input sanitising");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Davide Del Vecchio discovered a vulnerability in mpg123, a popular
(but non-free) MPEG layer 1/2/3 audio player. A malicious MPEG layer
2/3 file could cause the header checks in mpg123 to fail, which could
in turn allow arbitrary code to be executed with the privileges of the
user running mpg123."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-564"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mpg123 package.

For the stable distribution (woody) this problem has been fixed in
version 0.59r-13woody3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mpg123");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/06");
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
if (deb_check(release:"3.0", prefix:"mpg123", reference:"0.59r-13woody3")) flag++;
if (deb_check(release:"3.0", prefix:"mpg123-esd", reference:"0.59r-13woody3")) flag++;
if (deb_check(release:"3.0", prefix:"mpg123-nas", reference:"0.59r-13woody3")) flag++;
if (deb_check(release:"3.0", prefix:"mpg123-oss-3dnow", reference:"0.59r-13woody3")) flag++;
if (deb_check(release:"3.0", prefix:"mpg123-oss-i486", reference:"0.59r-13woody3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
