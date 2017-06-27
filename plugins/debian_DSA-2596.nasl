#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2596. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63359);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/16 15:37:39 $");

  script_osvdb_id(88843);
  script_xref(name:"DSA", value:"2596");

  script_name(english:"Debian DSA-2596-1 : mediawiki-extensions - XSS");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Thorsten Glaser discovered that the RSSReader extension for MediaWiki,
a website engine for collaborative work, does not properly escape tags
in feeds. This could allow a malicious feed to inject JavaScript into
the MediaWiki pages."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=696179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/mediawiki-extensions"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2596"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mediawiki-extensions packages.

For the stable distribution (squeeze), this problem has been fixed in
version 2.3squeeze2."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mediawiki-extensions");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/31");
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
if (deb_check(release:"6.0", prefix:"mediawiki-extensions", reference:"2.3squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"mediawiki-extensions-base", reference:"2.3squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"mediawiki-extensions-collection", reference:"2.3squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"mediawiki-extensions-confirmedit", reference:"2.3squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"mediawiki-extensions-fckeditor", reference:"2.3squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"mediawiki-extensions-geshi", reference:"2.3squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"mediawiki-extensions-graphviz", reference:"2.3squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"mediawiki-extensions-ldapauth", reference:"2.3squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"mediawiki-extensions-openid", reference:"2.3squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
