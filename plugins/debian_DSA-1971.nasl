#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1971. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44836);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/05/17 23:54:23 $");

  script_cve_id("CVE-2009-4012");
  script_osvdb_id(61715);
  script_xref(name:"DSA", value:"1971");

  script_name(english:"Debian DSA-1971-1 : libthai - integer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tim Starling discovered that libthai, a set of Thai language support
routines, is vulnerable of integer/heap overflow. This vulnerability
could allow an attacker to run arbitrary code by sending a very long
string."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-1971"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libthai package.

For the oldstable distribution (etch), this problem has been fixed in
version 0.1.6-1+etch1.

For the stable distribution (lenny), this problem has been fixed in
version 0.1.9-4+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libthai");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/15");
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
if (deb_check(release:"4.0", prefix:"libthai-dev", reference:"0.1.6-1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libthai-doc", reference:"0.1.6-1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libthai0", reference:"0.1.6-1+etch1")) flag++;
if (deb_check(release:"5.0", prefix:"libthai-data", reference:"0.1.9-4+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libthai-dev", reference:"0.1.9-4+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libthai-doc", reference:"0.1.9-4+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libthai0", reference:"0.1.9-4+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
