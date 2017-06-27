#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2046. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46346);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/05/03 11:20:11 $");

  script_cve_id("CVE-2010-0403", "CVE-2010-0404");
  script_osvdb_id(64638, 64639, 64738, 64739);
  script_xref(name:"DSA", value:"2046");

  script_name(english:"Debian DSA-2046-1 : phpgroupware - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in phpgroupware, a
Web-based groupware system written in PHP. The Common Vulnerabilities
and Exposures project identifies the following problems :

  - CVE-2010-0403
    A local file inclusion vulnerability allows remote
    attackers to execute arbitrary PHP code and include
    arbitrary local files.

  - CVE-2010-0404
    Multiple SQL injection vulnerabilities allows remote
    attackers to execute arbitrary SQL commands."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0403"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2046"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the phpgroupware package.

For the stable distribution (lenny), these problems have been fixed in
version 1:0.9.16.012+dfsg-8+lenny2"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:phpgroupware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"phpgroupware", reference:"1:0.9.16.012+dfsg-8+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"phpgroupware-0.9.16", reference:"1:0.9.16.012+dfsg-8+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"phpgroupware-0.9.16-addressbook", reference:"1:0.9.16.012+dfsg-8+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"phpgroupware-0.9.16-admin", reference:"1:0.9.16.012+dfsg-8+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"phpgroupware-0.9.16-calendar", reference:"1:0.9.16.012+dfsg-8+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"phpgroupware-0.9.16-core", reference:"1:0.9.16.012+dfsg-8+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"phpgroupware-0.9.16-core-base", reference:"1:0.9.16.012+dfsg-8+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"phpgroupware-0.9.16-doc", reference:"1:0.9.16.012+dfsg-8+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"phpgroupware-0.9.16-email", reference:"1:0.9.16.012+dfsg-8+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"phpgroupware-0.9.16-filemanager", reference:"1:0.9.16.012+dfsg-8+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"phpgroupware-0.9.16-manual", reference:"1:0.9.16.012+dfsg-8+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"phpgroupware-0.9.16-news-admin", reference:"1:0.9.16.012+dfsg-8+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"phpgroupware-0.9.16-notes", reference:"1:0.9.16.012+dfsg-8+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"phpgroupware-0.9.16-phpgwapi", reference:"1:0.9.16.012+dfsg-8+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"phpgroupware-0.9.16-phpgwapi-doc", reference:"1:0.9.16.012+dfsg-8+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"phpgroupware-0.9.16-preferences", reference:"1:0.9.16.012+dfsg-8+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"phpgroupware-0.9.16-setup", reference:"1:0.9.16.012+dfsg-8+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"phpgroupware-0.9.16-todo", reference:"1:0.9.16.012+dfsg-8+lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
