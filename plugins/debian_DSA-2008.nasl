#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2008. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45008);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/05/17 23:54:24 $");

  script_osvdb_id(62553, 62554, 62555, 62556);
  script_xref(name:"DSA", value:"2008");

  script_name(english:"Debian DSA-2008-1 : typo3-src - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in the TYPO3 web
content management framework: Cross-site scripting vulnerabilities
have been discovered in both the frontend and the backend. Also, user
data could be leaked. More details can be found in the Typo3 security
advisory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=571151"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://typo3.org/teams/security/security-bulletins/typo3-sa-2010-004/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2008"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the typo3-src package.

For the stable distribution (lenny), these problems have been fixed in
version 4.2.5-1+lenny3.

For the upcoming stable distribution (squeeze) and the unstable
distribution (sid), these problems have been fixed in version 4.3.2-1."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:typo3-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"typo3", reference:"4.2.5-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"typo3-src-4.2", reference:"4.2.5-1+lenny3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
