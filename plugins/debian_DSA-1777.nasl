#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1777. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36208);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2013/05/17 23:49:56 $");

  script_xref(name:"DSA", value:"1777");

  script_name(english:"Debian DSA-1777-1 : git-core - file permission error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Peter Palfrader discovered that in the Git revision control system, on
some architectures files under /usr/share/git-core/templates/ were
owned by a non-root user. This allows a user with that uid on the
local system to write to these files and possibly escalate their
privileges.

This issue only affects the DEC Alpha and MIPS (big and little endian)
architectures."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=516669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1777"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the git-core package.

For the old stable distribution (etch), this problem has been fixed in
version 1.4.4.4-4+etch2.

For the stable distribution (lenny), this problem has been fixed in
version 1.5.6.5-3+lenny1."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-core");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"git-arch", reference:"1.4.4.4-4+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"git-core", reference:"1.4.4.4-4+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"git-cvs", reference:"1.4.4.4-4+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"git-daemon-run", reference:"1.4.4.4-4+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"git-doc", reference:"1.4.4.4-4+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"git-email", reference:"1.4.4.4-4+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"git-svn", reference:"1.4.4.4-4+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"gitk", reference:"1.4.4.4-4+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"gitweb", reference:"1.4.4.4-4+etch2")) flag++;
if (deb_check(release:"5.0", prefix:"git-arch", reference:"1.5.6.5-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"git-core", reference:"1.5.6.5-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"git-cvs", reference:"1.5.6.5-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"git-daemon-run", reference:"1.5.6.5-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"git-doc", reference:"1.5.6.5-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"git-email", reference:"1.5.6.5-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"git-gui", reference:"1.5.6.5-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"git-svn", reference:"1.5.6.5-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"gitk", reference:"1.5.6.5-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"gitweb", reference:"1.5.6.5-3+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
