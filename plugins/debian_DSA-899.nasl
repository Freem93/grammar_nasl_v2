#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-899. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22765);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/06 20:34:49 $");

  script_cve_id("CVE-2005-0870", "CVE-2005-2600", "CVE-2005-3347", "CVE-2005-3348");
  script_osvdb_id(18699, 20821, 21159);
  script_xref(name:"DSA", value:"899");

  script_name(english:"Debian DSA-899-1 : egroupware - programming errors");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in egroupware, a
web-based groupware suite. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2005-0870
    Maksymilian Arciemowicz discovered several cross site
    scripting problems in phpsysinfo, which are also present
    in the imported version in egroupware and of which not
    all were fixed in DSA 724.

  - CVE-2005-2600
    Alexander Heidenreich discovered a cross-site scripting
    problem in the tree view of FUD Forum Bulletin Board
    Software, which is also present in egroupware and allows
    remote attackers to read private posts via a modified
    mid parameter.

  - CVE-2005-3347
    Christopher Kunz discovered that local variables get
    overwritten unconditionally in phpsysinfo, which are
    also present in egroupware, and are trusted later, which
    could lead to the inclusion of arbitrary files.

  - CVE-2005-3348
    Christopher Kunz discovered that user-supplied input is
    used unsanitised in phpsysinfo and imported in
    egroupware, causing a HTTP Response splitting problem."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=301118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-899"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the egroupware packages.

The old stable distribution (woody) does not contain egroupware
packages.

For the stable distribution (sarge) this problem has been fixed in
version 1.0.0.007-2.dfsg-2sarge4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(22, 352);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:egroupware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"egroupware", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-addressbook", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-bookmarks", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-calendar", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-comic", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-core", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-developer-tools", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-email", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-emailadmin", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-etemplate", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-felamimail", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-filemanager", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-forum", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-ftp", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-fudforum", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-headlines", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-infolog", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-jinn", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-ldap", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-manual", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-messenger", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-news-admin", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-phpbrain", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-phpldapadmin", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-phpsysinfo", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-polls", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-projects", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-registration", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-sitemgr", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-stocks", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-tts", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-wiki", reference:"1.0.0.007-2.dfsg-2sarge4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
