#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1911. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44776);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/05/17 23:54:23 $");

  script_cve_id("CVE-2009-2940");
  script_osvdb_id(59028);
  script_xref(name:"DSA", value:"1911");

  script_name(english:"Debian DSA-1911-1 : pygresql - missing escape function");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that pygresql, a PostgreSQL module for Python, was
missing a function to call PQescapeStringConn(). This is needed,
because PQescapeStringConn() honours the charset of the connection and
prevents insufficient escaping, when certain multibyte character
encodings are used. The new function is called pg_escape_string(),
which takes the database connection as a first argument. The old
function escape_string() has been preserved as well for backwards
compatibility.

Developers using these bindings are encouraged to adjust their code to
use the new function."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1911"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the pygresql packages.

For the oldstable distribution (etch), this problem has been fixed in
version 1:3.8.1-1etch2.

For the stable distribution (lenny), this problem has been fixed in
version 1:3.8.1-3+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pygresql");
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
if (deb_check(release:"4.0", prefix:"python-pygresql", reference:"1:3.8.1-1etch2")) flag++;
if (deb_check(release:"5.0", prefix:"python-pygresql", reference:"1:3.8.1-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"python-pygresql-dbg", reference:"1:3.8.1-3+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
