#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-748. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18663);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/05/18 00:15:58 $");

  script_cve_id("CVE-2005-1992");
  script_xref(name:"DSA", value:"748");

  script_name(english:"Debian DSA-748-1 : ruby1.8 - bad default value");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability has been discovered in ruby1.8 that could allow
arbitrary command execution on a server running the ruby xmlrpc
server. 

The old stable distribution (woody) did not include ruby1.8.

This problem is fixed for the current stable distribution (sarge) in
version 1.8.2-7sarge1.

This problem is fixed for the unstable distribution in version
1.8.2-8."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-748"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the ruby1.8 package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/11");
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
if (deb_check(release:"3.1", prefix:"irb1.8", reference:"1.8.2-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libdbm-ruby1.8", reference:"1.8.2-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libgdbm-ruby1.8", reference:"1.8.2-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libopenssl-ruby1.8", reference:"1.8.2-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libreadline-ruby1.8", reference:"1.8.2-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libruby1.8", reference:"1.8.2-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libruby1.8-dbg", reference:"1.8.2-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libtcltk-ruby1.8", reference:"1.8.2-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"rdoc1.8", reference:"1.8.2-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"ri1.8", reference:"1.8.2-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"ruby1.8", reference:"1.8.2-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"ruby1.8-dev", reference:"1.8.2-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"ruby1.8-elisp", reference:"1.8.2-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"ruby1.8-examples", reference:"1.8.2-7sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
