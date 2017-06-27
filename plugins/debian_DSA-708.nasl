#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-708. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18053);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/18 00:15:58 $");

  script_cve_id("CVE-2005-0525");
  script_osvdb_id(15184);
  script_xref(name:"DSA", value:"708");

  script_name(english:"Debian DSA-708-1 : php3 - missing input sanitising");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An iDEFENSE researcher discovered two problems in the image processing
functions of PHP, a server-side, HTML-embedded scripting language, of
which one is present in PHP3 as well. When reading a JPEG image, PHP
can be tricked into an endless loop due to insufficient input
validation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=302701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-708"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the php3 package.

For the stable distribution (woody) this problem has been fixed in
version 3.0.18-23.1woody3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/15");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"php3", reference:"3.0.18-23.1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php3-cgi", reference:"3.0.18-23.1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php3-cgi-gd", reference:"3.0.18-23.1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php3-cgi-imap", reference:"3.0.18-23.1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php3-cgi-ldap", reference:"3.0.18-23.1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php3-cgi-magick", reference:"3.0.18-23.1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php3-cgi-mhash", reference:"3.0.18-23.1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php3-cgi-mysql", reference:"3.0.18-23.1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php3-cgi-snmp", reference:"3.0.18-23.1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php3-cgi-xml", reference:"3.0.18-23.1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php3-dev", reference:"3.0.18-23.1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php3-doc", reference:"3.0.18-23.1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php3-gd", reference:"3.0.18-23.1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php3-imap", reference:"3.0.18-23.1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php3-ldap", reference:"3.0.18-23.1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php3-magick", reference:"3.0.18-23.1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php3-mhash", reference:"3.0.18-23.1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php3-mysql", reference:"3.0.18-23.1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php3-snmp", reference:"3.0.18-23.1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php3-xml", reference:"3.0.18-23.1woody3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
