#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3015. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77468);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/04/03 14:49:08 $");

  script_cve_id("CVE-2014-5461");
  script_bugtraq_id(69342);
  script_osvdb_id(105211);
  script_xref(name:"DSA", value:"3015");

  script_name(english:"Debian DSA-3015-1 : lua5.1 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A heap-based overflow vulnerability was found in the way Lua, a
simple, extensible, embeddable programming language, handles varargs
functions with many fixed parameters called with few arguments,
leading to application crashes or, potentially, arbitrary code
execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/lua5.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-3015"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the lua5.1 packages.

For the stable distribution (wheezy), this problem has been fixed in
version 5.1.5-4+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lua5.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"liblua5.1-0", reference:"5.1.5-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"liblua5.1-0-dbg", reference:"5.1.5-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"liblua5.1-0-dev", reference:"5.1.5-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"lua5.1", reference:"5.1.5-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"lua5.1-doc", reference:"5.1.5-4+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
