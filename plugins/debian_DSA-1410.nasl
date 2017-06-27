#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1410. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28299);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2007-5162", "CVE-2007-5770");
  script_osvdb_id(40773);
  script_xref(name:"DSA", value:"1410");

  script_name(english:"Debian DSA-1410-1 : ruby1.8 - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Ruby, an
object-oriented scripting language. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2007-5162
    It was discovered that the Ruby HTTP(S) module performs
    insufficient validation of SSL certificates, which may
    lead to man-in-the-middle attacks.

  - CVE-2007-5770
    It was discovered that the Ruby modules for FTP, Telnet,
    IMAP, POP and SMTP perform insufficient validation of
    SSL certificates, which may lead to man-in-the-middle
    attacks."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1410"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ruby1.8 packages.

For the old stable distribution (sarge) these problems have been fixed
in version 1.8.2-7sarge6. Packages for sparc will be provided later.

For the stable distribution (etch) these problems have been fixed in
version 1.8.5-4etch1. Packages for sparc will be provided later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cwe_id(287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"irb1.8", reference:"1.8.2-7sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"libdbm-ruby1.8", reference:"1.8.2-7sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"libgdbm-ruby1.8", reference:"1.8.2-7sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"libopenssl-ruby1.8", reference:"1.8.2-7sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"libreadline-ruby1.8", reference:"1.8.2-7sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"libruby1.8", reference:"1.8.2-7sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"libruby1.8-dbg", reference:"1.8.2-7sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"libtcltk-ruby1.8", reference:"1.8.2-7sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"rdoc1.8", reference:"1.8.2-7sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"ri1.8", reference:"1.8.2-7sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"ruby1.8", reference:"1.8.2-7sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"ruby1.8-dev", reference:"1.8.2-7sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"ruby1.8-elisp", reference:"1.8.2-7sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"ruby1.8-examples", reference:"1.8.2-7sarge6")) flag++;
if (deb_check(release:"4.0", prefix:"irb1.8", reference:"1.8.5-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libdbm-ruby1.8", reference:"1.8.5-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgdbm-ruby1.8", reference:"1.8.5-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libopenssl-ruby1.8", reference:"1.8.5-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libreadline-ruby1.8", reference:"1.8.5-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libruby1.8", reference:"1.8.5-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libruby1.8-dbg", reference:"1.8.5-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libtcltk-ruby1.8", reference:"1.8.5-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"rdoc1.8", reference:"1.8.5-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"ri1.8", reference:"1.8.5-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"ruby1.8", reference:"1.8.5-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"ruby1.8-dev", reference:"1.8.5-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"ruby1.8-elisp", reference:"1.8.5-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"ruby1.8-examples", reference:"1.8.5-4etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
