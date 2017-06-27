#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-747. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18662);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/06/14 17:29:37 $");

  script_cve_id("CVE-2005-1921");
  script_osvdb_id(17793);
  script_xref(name:"DSA", value:"747");

  script_name(english:"Debian DSA-747-1 : egroupware - input validation error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability has been identified in the xmlrpc library included in
the egroupware package. This vulnerability could lead to the execution
of arbitrary commands on the server running egroupware.

The old stable distribution (woody) did not include egroupware."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-747"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the egroupware package.

For the current stable distribution (sarge), this problem is fixed in
version 1.0.0.007-2.dfsg-2sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP XML-RPC Arbitrary Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:egroupware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/11");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"egroupware", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-addressbook", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-bookmarks", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-calendar", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-comic", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-core", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-developer-tools", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-email", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-emailadmin", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-etemplate", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-felamimail", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-filemanager", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-forum", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-ftp", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-fudforum", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-headlines", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-infolog", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-jinn", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-ldap", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-manual", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-messenger", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-news-admin", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-phpbrain", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-phpldapadmin", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-phpsysinfo", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-polls", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-projects", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-registration", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-sitemgr", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-stocks", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-tts", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"egroupware-wiki", reference:"1.0.0.007-2.dfsg-2sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
