#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-419. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15256);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2013/11/05 11:41:02 $");

  script_cve_id("CVE-2004-0016", "CVE-2004-0017");
  script_bugtraq_id(9386, 9387);
  script_osvdb_id(2691, 6857, 6860);
  script_xref(name:"DSA", value:"419");

  script_name(english:"Debian DSA-419-1 : phpgroupware - missing filename sanitising, SQL injection");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The authors of phpgroupware, a web-based groupware system written in
PHP, discovered several vulnerabilities. The Common Vulnerabilities
and Exposures project identifies the following problems :

  - CAN-2004-0016
    In the 'calendar' module, 'save extension' was not
    enforced for holiday files. As a result, server-side php
    scripts may be placed in directories that then could be
    accessed remotely and cause the webserver to execute
    those. This was resolved by enforcing the extension
    '.txt' for holiday files.

  - CAN-2004-0017

    Some SQL injection problems (non-escaping of values used
    in SQL strings) the 'calendar' and 'infolog' modules.

Additionally, the Debian maintainer adjusted the permissions on world
writable directories that were accidentally created by former postinst
during the installation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-419"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the phpgroupware, phpgroupware-calendar and
phpgroupware-infolog packages.

For the stable distribution (woody) this problem has been fixed in
version 0.9.14-0.RC3.2.woody3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:phpgroupware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/10/21");
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
if (deb_check(release:"3.0", prefix:"phpgroupware", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-addressbook", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-admin", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-api", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-api-doc", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-bookkeeping", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-bookmarks", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-brewer", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-calendar", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-chat", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-chora", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-comic", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-core", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-core-doc", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-developer-tools", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-dj", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-eldaptir", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-email", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-filemanager", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-forum", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-ftp", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-headlines", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-hr", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-img", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-infolog", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-inv", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-manual", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-messenger", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-napster", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-news-admin", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-nntp", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-notes", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-phonelog", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-phpsysinfo", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-phpwebhosting", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-polls", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-preferences", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-projects", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-registration", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-setup", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-skel", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-soap", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-stocks", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-todo", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-tts", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-wap", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-weather", reference:"0.9.14-0.RC3.2.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"phpgroupware-xmlrpc", reference:"0.9.14-0.RC3.2.woody3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
