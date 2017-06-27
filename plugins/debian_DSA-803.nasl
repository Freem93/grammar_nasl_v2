#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-803. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19610);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/18 00:15:59 $");

  script_cve_id("CVE-2005-2088");
  script_osvdb_id(17738);
  script_xref(name:"DSA", value:"803");

  script_name(english:"Debian DSA-803-1 : apache - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability has been discovered in the Apache web server. When it
is acting as an HTTP proxy, it allows remote attackers to poison the
web cache, bypass web application firewall protection, and conduct
cross-site scripting attacks, which causes Apache to incorrectly
handle and forward the body of the request.

The fix for this bug is contained in the apache-common package which
means that there isn't any need for a separate update of the
apache-perl and apache-ssl package."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=322607"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-803"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Apache package.

For the old stable distribution (woody) this problem has been fixed in
version 1.3.26-0woody7.

For the stable distribution (sarge) this problem has been fixed in
version 1.3.33-6sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/06");
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
if (deb_check(release:"3.0", prefix:"apache", reference:"1.3.26-0woody7")) flag++;
if (deb_check(release:"3.0", prefix:"apache-common", reference:"1.3.26-0woody7")) flag++;
if (deb_check(release:"3.0", prefix:"apache-dev", reference:"1.3.26-0woody7")) flag++;
if (deb_check(release:"3.0", prefix:"apache-doc", reference:"1.3.26-0woody7")) flag++;
if (deb_check(release:"3.1", prefix:"apache", reference:"1.3.33-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"apache-common", reference:"1.3.33-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"apache-dbg", reference:"1.3.33-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"apache-dev", reference:"1.3.33-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"apache-doc", reference:"1.3.33-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"apache-perl", reference:"1.3.33-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"apache-ssl", reference:"1.3.33-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"apache-utils", reference:"1.3.33-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libapache-mod-perl", reference:"1.29.0.3-6sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
