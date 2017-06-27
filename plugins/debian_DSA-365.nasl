#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-365. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15202);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2014/04/30 10:43:34 $");

  script_cve_id("CVE-2003-0504", "CVE-2003-0599", "CVE-2003-0657");
  script_bugtraq_id(8088);
  script_osvdb_id(2243, 6858, 6859);
  script_xref(name:"DSA", value:"365");

  script_name(english:"Debian DSA-365-1 : phpgroupware - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in phpgroupware :

  - CAN-2003-0504: Multiple cross-site scripting (XSS)
    vulnerabilities in Phpgroupware 0.9.14.003 (aka
    webdistro) allow remote attackers to insert arbitrary
    HTML or web script, as demonstrated with a request to
    index.php in the addressbook module.
  - CAN-2003-0599: Unknown vulnerability in the Virtual File
    System (VFS) capability for phpGroupWare 0.9.16preRC and
    versions before 0.9.14.004 with unknown implications,
    related to the VFS path being under the web document
    root.

  - CAN-2003-0657: Multiple SQL injection vulnerabilities in
    the infolog module of phpgroupware could allow remote
    attackers to execute arbitrary SQL statements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/201980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-365"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the stable distribution (woody), these problems have been fixed in
version 0.9.14-0.RC3.2.woody2.


We recommend that you update your phpgroupware package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:phpgroupware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/07/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"phpgroupware", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-addressbook", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-admin", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-api", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-api-doc", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-bookkeeping", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-bookmarks", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-brewer", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-calendar", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-chat", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-chora", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-comic", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-core", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-core-doc", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-developer-tools", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-dj", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-eldaptir", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-email", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-filemanager", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-forum", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-ftp", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-headlines", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-hr", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-img", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-infolog", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-inv", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-manual", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-messenger", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-napster", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-news-admin", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-nntp", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-notes", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-phonelog", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-phpsysinfo", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-phpwebhosting", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-polls", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-preferences", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-projects", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-registration", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-setup", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-skel", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-soap", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-stocks", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-todo", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-tts", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-wap", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-weather", reference:"0.9.14-0.RC3.2.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-xmlrpc", reference:"0.9.14-0.RC3.2.woody2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
