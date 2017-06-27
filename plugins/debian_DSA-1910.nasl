#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1910. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44775);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/05/17 23:54:23 $");

  script_cve_id("CVE-2009-2942");
  script_osvdb_id(59030);
  script_xref(name:"DSA", value:"1910");

  script_name(english:"Debian DSA-1910-1 : mysql-ocaml - missing escape function");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that mysql-ocaml, OCaml bindings for MySql, was
missing a function to call mysql_real_escape_string(). This is needed,
because mysql_real_escape_string() honours the charset of the
connection and prevents insufficient escaping, when certain multibyte
character encodings are used. The added function is called
real_escape() and takes the established database connection as a first
argument. The old escape_string() was kept for backwards
compatibility.

Developers using these bindings are encouraged to adjust their code to
use the new function."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1910"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mysql-ocaml packages.

For the oldstable distribution (etch), this problem has been fixed in
version 1.0.4-2+etch1.

For the stable distribution (lenny), this problem has been fixed in
version 1.0.4-4+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-ocaml");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libmysql-ocaml", reference:"1.0.4-2+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmysql-ocaml-dev", reference:"1.0.4-2+etch1")) flag++;
if (deb_check(release:"5.0", prefix:"libmysql-ocaml", reference:"1.0.4-4+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libmysql-ocaml-dev", reference:"1.0.4-4+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
