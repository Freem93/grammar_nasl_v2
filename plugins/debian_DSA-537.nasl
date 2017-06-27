#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-537. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15374);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2013/05/18 00:11:36 $");

  script_cve_id("CVE-2004-0755");
  script_osvdb_id(8845);
  script_xref(name:"DSA", value:"537");

  script_name(english:"Debian DSA-537-1 : ruby - insecure file permissions");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Andres Salomon noticed a problem in the CGI session management of
Ruby, an object-oriented scripting language. CGI::Session's FileStore
(and presumably PStore, but not in Debian woody) implementations store
session information insecurely. They simply create files, ignoring
permission issues. This can lead an attacker who has also shell access
to the webserver to take over a session."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=260779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-537"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libruby package.

For the stable distribution (woody) this problem has been fixed in
version 1.6.7-3woody3.

For the unstable and testing distributions (sid and sarge) this
problem has been fixed in version 1.8.1+1.8.2pre1-4."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/16");
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
if (deb_check(release:"3.0", prefix:"irb", reference:"1.6.7-3woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libcurses-ruby", reference:"1.6.7-3woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libdbm-ruby", reference:"1.6.7-3woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libgdbm-ruby", reference:"1.6.7-3woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libnkf-ruby", reference:"1.6.7-3woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libpty-ruby", reference:"1.6.7-3woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libreadline-ruby", reference:"1.6.7-3woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libruby", reference:"1.6.7-3woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libsdbm-ruby", reference:"1.6.7-3woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libsyslog-ruby", reference:"1.6.7-3woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libtcltk-ruby", reference:"1.6.7-3woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libtk-ruby", reference:"1.6.7-3woody3")) flag++;
if (deb_check(release:"3.0", prefix:"ruby", reference:"1.6.7-3woody3")) flag++;
if (deb_check(release:"3.0", prefix:"ruby-dev", reference:"1.6.7-3woody3")) flag++;
if (deb_check(release:"3.0", prefix:"ruby-elisp", reference:"1.6.7-3woody3")) flag++;
if (deb_check(release:"3.0", prefix:"ruby-examples", reference:"1.6.7-3woody3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
