#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-842. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19846);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/07/10 14:11:55 $");

  script_cve_id("CVE-2005-2498");
  script_osvdb_id(18889);
  script_xref(name:"DSA", value:"842");

  script_name(english:"Debian DSA-842-1 : egroupware - missing input sanitising");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Stefan Esser discovered a vulnerability in the XML-RPC libraries which
are also present in egroupware, a web-based groupware suite, that
allows injection of arbitrary PHP code into eval() statements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=323350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-842"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the egroupware packages.

The old stable distribution (woody) does not contain egroupware
packages.

For the stable distribution (sarge) this problem has been fixed in
version 1.0.0.007-2.dfsg-2sarge2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:egroupware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"egroupware", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-addressbook", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-bookmarks", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-calendar", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-comic", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-core", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-developer-tools", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-email", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-emailadmin", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-etemplate", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-felamimail", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-filemanager", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-forum", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-ftp", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-fudforum", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-headlines", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-infolog", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-jinn", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-ldap", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-manual", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-messenger", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-news-admin", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-phpbrain", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-phpldapadmin", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-phpsysinfo", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-polls", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-projects", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-registration", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-sitemgr", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-stocks", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-tts", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-wiki", reference:"1.0.0.007-2.dfsg-2sarge2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
