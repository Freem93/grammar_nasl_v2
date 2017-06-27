#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-798. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19568);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/11/05 11:41:02 $");

  script_cve_id("CVE-2005-2498", "CVE-2005-2600", "CVE-2005-2761");
  script_osvdb_id(18979);
  script_xref(name:"DSA", value:"798");

  script_name(english:"Debian DSA-798-1 : phpgroupware - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in phpgroupware, a
web-based groupware system written in PHP. The Common Vulnerabilities
and Exposures project identifies the following problems :

  - CAN-2005-2498
    Stefan Esser discovered another vulnerability in the
    XML-RPC libraries that allows injection of arbitrary PHP
    code into eval() statements. The XMLRPC component has
    been disabled.

  - CAN-2005-2600

    Alexander Heidenreich discovered a cross-site scripting
    problem in the tree view of FUD Forum Bulletin Board
    Software, which is also present in phpgroupware.

  - CAN-2005-2761

    A global cross-site scripting fix has also been included
    that protects against potential malicious scripts
    embedded in CSS and xmlns in various parts of the
    application and modules.

This update also contains a postinst bugfix that has been approved for
the next update to the stable release."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-798"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the phpgroupware packages.

For the old stable distribution (woody) these problems don't apply.

For the stable distribution (sarge) these problems have been fixed in
version 0.9.16.005-3.sarge2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:phpgroupware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/25");
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
if (deb_check(release:"3.1", prefix:"phpgroupware", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-addressbook", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-admin", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-bookmarks", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-calendar", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-chat", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-comic", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-core", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-developer-tools", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-dj", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-eldaptir", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-email", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-etemplate", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-felamimail", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-filemanager", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-folders", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-forum", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-ftp", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-fudforum", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-headlines", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-hr", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-img", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-infolog", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-manual", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-messenger", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-news-admin", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-nntp", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-notes", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-phonelog", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-phpbrain", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-phpgwapi", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-phpsysinfo", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-polls", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-preferences", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-projects", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-qmailldap", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-registration", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-setup", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-sitemgr", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-skel", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-soap", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-stocks", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-todo", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-tts", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-wiki", reference:"0.9.16.005-3.sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-xmlrpc", reference:"0.9.16.005-3.sarge2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
