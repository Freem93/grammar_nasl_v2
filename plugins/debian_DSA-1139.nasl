#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1139. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22681);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/05/17 23:36:52 $");

  script_cve_id("CVE-2006-3694");
  script_osvdb_id(27144);
  script_xref(name:"DSA", value:"1139");

  script_name(english:"Debian DSA-1139-1 : ruby1.6 - missing privilege checks");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the interpreter for the Ruby language does not
properly maintain 'safe levels' for aliasing, directory accesses and
regular expressions, which might lead to a bypass of security
restrictions."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=378029"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1139"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Ruby packages.

For the stable distribution (sarge) this problem has been fixed in
version 1.6.8-12sarge2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"irb1.6", reference:"1.6.8-12sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libcurses-ruby1.6", reference:"1.6.8-12sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libdbm-ruby1.6", reference:"1.6.8-12sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libgdbm-ruby1.6", reference:"1.6.8-12sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libpty-ruby1.6", reference:"1.6.8-12sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libreadline-ruby1.6", reference:"1.6.8-12sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libruby1.6", reference:"1.6.8-12sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libruby1.6-dbg", reference:"1.6.8-12sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libsdbm-ruby1.6", reference:"1.6.8-12sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libsyslog-ruby1.6", reference:"1.6.8-12sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libtcltk-ruby1.6", reference:"1.6.8-12sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libtk-ruby1.6", reference:"1.6.8-12sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"ruby1.6", reference:"1.6.8-12sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"ruby1.6-dev", reference:"1.6.8-12sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"ruby1.6-elisp", reference:"1.6.8-12sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"ruby1.6-examples", reference:"1.6.8-12sarge2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
