#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1854. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44719);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/05 14:49:56 $");

  script_cve_id("CVE-2009-2412");
  script_bugtraq_id(35949);
  script_osvdb_id(56765, 56766);
  script_xref(name:"DSA", value:"1854");

  script_name(english:"Debian DSA-1854-1 : apr, apr-util - heap buffer overflow");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Matt Lewis discovered that the memory management code in the Apache
Portable Runtime (APR) library does not guard against a wrap-around
during size computations. This could cause the library to return a
memory area which smaller than requested, resulting a heap overflow
and possibly arbitrary code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1854"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the APR packages.

For the old stable distribution (etch), this problem has been fixed in
version 1.2.7-9 of the apr package, and version 1.2.7+dfsg-2+etch3 of
the apr-util package.

For the stable distribution (lenny), this problem has been fixed in
version 1.2.12-5+lenny1 of the apr package and version 1.2.12-5+lenny1
of the apr-util package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apr-util");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libapr1", reference:"1.2.7-9")) flag++;
if (deb_check(release:"4.0", prefix:"libapr1-dbg", reference:"1.2.7-9")) flag++;
if (deb_check(release:"4.0", prefix:"libapr1-dev", reference:"1.2.7-9")) flag++;
if (deb_check(release:"4.0", prefix:"libaprutil1", reference:"1.2.7+dfsg-2+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libaprutil1-dbg", reference:"1.2.7+dfsg-2+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libaprutil1-dev", reference:"1.2.7+dfsg-2+etch3")) flag++;
if (deb_check(release:"5.0", prefix:"libapr1", reference:"1.2.12-5+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libapr1-dbg", reference:"1.2.12-5+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libapr1-dev", reference:"1.2.12-5+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libaprutil1", reference:"1.2.12+dfsg-8+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libaprutil1-dbg", reference:"1.2.12+dfsg-8+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libaprutil1-dev", reference:"1.2.12+dfsg-8+lenny4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
