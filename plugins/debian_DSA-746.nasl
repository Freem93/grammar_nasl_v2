#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-746. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19195);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/18 00:15:58 $");

  script_cve_id("CVE-2005-1921");
  script_xref(name:"DSA", value:"746");

  script_name(english:"Debian DSA-746-1 : phpgroupware - input validation error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability had been identified in the xmlrpc library included
with phpgroupware, a web-based application including email, calendar
and other groupware functionality. This vulnerability could lead to
the execution of arbitrary commands on the server running
phpgroupware.

The security team is continuing to investigate the version of
phpgroupware included with the old stable distribution (woody). At
this time we recommend disabling phpgroupware or upgrading to the
current stable distribution (sarge)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-746"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the phpgroupware package.

For the current stable distribution (sarge) this problem has been
fixed in version 0.9.16.005-3.sarge0."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP XML-RPC Arbitrary Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:phpgroupware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/14");
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
if (deb_check(release:"3.1", prefix:"phpgroupware", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-addressbook", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-admin", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-bookmarks", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-calendar", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-chat", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-comic", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-core", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-developer-tools", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-dj", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-eldaptir", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-email", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-etemplate", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-felamimail", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-filemanager", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-folders", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-forum", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-ftp", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-fudforum", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-headlines", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-hr", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-img", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-infolog", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-manual", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-messenger", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-news-admin", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-nntp", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-notes", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-phonelog", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-phpbrain", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-phpgwapi", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-phpsysinfo", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-polls", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-preferences", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-projects", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-qmailldap", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-registration", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-setup", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-sitemgr", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-skel", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-soap", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-stocks", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-todo", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-tts", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-wiki", reference:"0.9.16.005-3.sarge0")) flag++;
if (deb_check(release:"3.1", prefix:"phpgroupware-xmlrpc", reference:"0.9.16.005-3.sarge0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
