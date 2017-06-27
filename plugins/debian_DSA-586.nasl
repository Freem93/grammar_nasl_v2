#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-586. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15684);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/18 00:11:36 $");

  script_cve_id("CVE-2004-0983");
  script_osvdb_id(11534);
  script_xref(name:"DSA", value:"586");

  script_name(english:"Debian DSA-586-1 : ruby - infinite loop");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The upstream developers of Ruby have corrected a problem in the CGI
module for this language. Specially crafted requests could cause an
infinite loop and thus cause the program to eat up cpu cycles."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-586"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ruby packages.

For the stable distribution (woody) this problem has been fixed in
version 1.6.7-3woody4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/08");
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
if (deb_check(release:"3.0", prefix:"irb", reference:"1.6.7-3woody4")) flag++;
if (deb_check(release:"3.0", prefix:"libcurses-ruby", reference:"1.6.7-3woody4")) flag++;
if (deb_check(release:"3.0", prefix:"libdbm-ruby", reference:"1.6.7-3woody4")) flag++;
if (deb_check(release:"3.0", prefix:"libgdbm-ruby", reference:"1.6.7-3woody4")) flag++;
if (deb_check(release:"3.0", prefix:"libnkf-ruby", reference:"1.6.7-3woody4")) flag++;
if (deb_check(release:"3.0", prefix:"libpty-ruby", reference:"1.6.7-3woody4")) flag++;
if (deb_check(release:"3.0", prefix:"libreadline-ruby", reference:"1.6.7-3woody4")) flag++;
if (deb_check(release:"3.0", prefix:"libruby", reference:"1.6.7-3woody4")) flag++;
if (deb_check(release:"3.0", prefix:"libsdbm-ruby", reference:"1.6.7-3woody4")) flag++;
if (deb_check(release:"3.0", prefix:"libsyslog-ruby", reference:"1.6.7-3woody4")) flag++;
if (deb_check(release:"3.0", prefix:"libtcltk-ruby", reference:"1.6.7-3woody4")) flag++;
if (deb_check(release:"3.0", prefix:"libtk-ruby", reference:"1.6.7-3woody4")) flag++;
if (deb_check(release:"3.0", prefix:"ruby", reference:"1.6.7-3woody4")) flag++;
if (deb_check(release:"3.0", prefix:"ruby-dev", reference:"1.6.7-3woody4")) flag++;
if (deb_check(release:"3.0", prefix:"ruby-elisp", reference:"1.6.7-3woody4")) flag++;
if (deb_check(release:"3.0", prefix:"ruby-examples", reference:"1.6.7-3woody4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
