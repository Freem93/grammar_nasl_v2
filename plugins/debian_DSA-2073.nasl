#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2073. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47791);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/06/04 10:44:09 $");

  script_cve_id("CVE-2009-4896");
  script_osvdb_id(66515);
  script_xref(name:"DSA", value:"2073");

  script_name(english:"Debian DSA-2073-1 : mlmmj - insufficient input sanitising");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Florian Streibelt reported a directory traversal flaw in the way the
Mailing List Managing Made Joyful mailing list manager processed
users' requests originating from the administrator web interface
without enough input validation. A remote, authenticated attacker
could use these flaws to write and/or delete arbitrary files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2073"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mlmmj package.

For the stable distribution (lenny), these problems have been fixed in
version 1.2.15-1.1+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mlmmj");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"mlmmj", reference:"1.2.15-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"mlmmj-php-web", reference:"1.2.15-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"mlmmj-php-web-admin", reference:"1.2.15-1.1+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
