#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2013. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45055);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/04/07 13:27:20 $");

  script_cve_id("CVE-2010-3313", "CVE-2010-3314");
  script_bugtraq_id(73832);
  script_osvdb_id(62804, 62805);
  script_xref(name:"DSA", value:"2013");

  script_name(english:"Debian DSA-2013-1 : egroupware - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Nahuel Grisolia discovered two vulnerabilities in Egroupware, a
web-based groupware suite: Missing input sanitising in the
spellchecker integration may lead to the execution of arbitrary
commands and a cross-site scripting vulnerability was discovered in
the login page."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=573279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2013"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the egroupware packages.

For the stable distribution (lenny), these problems have been fixed in
version 1.4.004-2.dfsg-4.2.

The upcoming stable distribution (squeeze), no longer contains
egroupware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:egroupware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"egroupware", reference:"1.4.004-2.dfsg-4.2")) flag++;
if (deb_check(release:"5.0", prefix:"egroupware-addressbook", reference:"1.4.004-2.dfsg-4.2")) flag++;
if (deb_check(release:"5.0", prefix:"egroupware-bookmarks", reference:"1.4.004-2.dfsg-4.2")) flag++;
if (deb_check(release:"5.0", prefix:"egroupware-calendar", reference:"1.4.004-2.dfsg-4.2")) flag++;
if (deb_check(release:"5.0", prefix:"egroupware-core", reference:"1.4.004-2.dfsg-4.2")) flag++;
if (deb_check(release:"5.0", prefix:"egroupware-developer-tools", reference:"1.4.004-2.dfsg-4.2")) flag++;
if (deb_check(release:"5.0", prefix:"egroupware-emailadmin", reference:"1.4.004-2.dfsg-4.2")) flag++;
if (deb_check(release:"5.0", prefix:"egroupware-etemplate", reference:"1.4.004-2.dfsg-4.2")) flag++;
if (deb_check(release:"5.0", prefix:"egroupware-felamimail", reference:"1.4.004-2.dfsg-4.2")) flag++;
if (deb_check(release:"5.0", prefix:"egroupware-filemanager", reference:"1.4.004-2.dfsg-4.2")) flag++;
if (deb_check(release:"5.0", prefix:"egroupware-infolog", reference:"1.4.004-2.dfsg-4.2")) flag++;
if (deb_check(release:"5.0", prefix:"egroupware-manual", reference:"1.4.004-2.dfsg-4.2")) flag++;
if (deb_check(release:"5.0", prefix:"egroupware-mydms", reference:"1.4.004-2.dfsg-4.2")) flag++;
if (deb_check(release:"5.0", prefix:"egroupware-news-admin", reference:"1.4.004-2.dfsg-4.2")) flag++;
if (deb_check(release:"5.0", prefix:"egroupware-phpbrain", reference:"1.4.004-2.dfsg-4.2")) flag++;
if (deb_check(release:"5.0", prefix:"egroupware-phpsysinfo", reference:"1.4.004-2.dfsg-4.2")) flag++;
if (deb_check(release:"5.0", prefix:"egroupware-polls", reference:"1.4.004-2.dfsg-4.2")) flag++;
if (deb_check(release:"5.0", prefix:"egroupware-projectmanager", reference:"1.4.004-2.dfsg-4.2")) flag++;
if (deb_check(release:"5.0", prefix:"egroupware-registration", reference:"1.4.004-2.dfsg-4.2")) flag++;
if (deb_check(release:"5.0", prefix:"egroupware-resources", reference:"1.4.004-2.dfsg-4.2")) flag++;
if (deb_check(release:"5.0", prefix:"egroupware-sambaadmin", reference:"1.4.004-2.dfsg-4.2")) flag++;
if (deb_check(release:"5.0", prefix:"egroupware-sitemgr", reference:"1.4.004-2.dfsg-4.2")) flag++;
if (deb_check(release:"5.0", prefix:"egroupware-timesheet", reference:"1.4.004-2.dfsg-4.2")) flag++;
if (deb_check(release:"5.0", prefix:"egroupware-tracker", reference:"1.4.004-2.dfsg-4.2")) flag++;
if (deb_check(release:"5.0", prefix:"egroupware-wiki", reference:"1.4.004-2.dfsg-4.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
