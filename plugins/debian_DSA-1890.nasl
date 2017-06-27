#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1890. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44755);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/03/30 13:45:22 $");

  script_cve_id("CVE-2009-2369");
  script_bugtraq_id(35552);
  script_xref(name:"DSA", value:"1890");

  script_name(english:"Debian DSA-1890-1 : wxwindows2.4 wxwidgets2.6 wxwidgets2.8 - integer overflow");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tielei Wang has discovered an integer overflow in wxWidgets, the
wxWidgets Cross-platform C++ GUI toolkit, which allows the execution
of arbitrary code via a crafted JPEG file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1890"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wxwidgets packages.

For the oldstable distribution (etch), this problem has been fixed in
version 2.4.5.1.1+etch1 for wxwindows2.4 and version 2.6.3.2.1.5+etch1
for wxwidgets2.6.

For the stable distribution (lenny), this problem has been fixed in
version 2.6.3.2.2-3+lenny1 for wxwidgets2.6 and version
2.8.7.1-1.1+lenny1 for wxwidgets2.8."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wxwidgets2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wxwidgets2.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wxwindows2.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libwxbase2.4-1", reference:"2.4.5.1.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libwxbase2.4-dbg", reference:"2.4.5.1.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libwxbase2.4-dev", reference:"2.4.5.1.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libwxbase2.6-0", reference:"2.6.3.2.1.5+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libwxbase2.6-dbg", reference:"2.6.3.2.1.5+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libwxbase2.6-dev", reference:"2.6.3.2.1.5+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libwxgtk2.4-1", reference:"2.4.5.1.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libwxgtk2.4-1-contrib", reference:"2.4.5.1.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libwxgtk2.4-contrib-dev", reference:"2.4.5.1.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libwxgtk2.4-dbg", reference:"2.4.5.1.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libwxgtk2.4-dev", reference:"2.4.5.1.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libwxgtk2.6-0", reference:"2.6.3.2.1.5+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libwxgtk2.6-dbg", reference:"2.6.3.2.1.5+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libwxgtk2.6-dev", reference:"2.6.3.2.1.5+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"python-wxgtk2.4", reference:"2.4.5.1.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"python-wxgtk2.6", reference:"2.6.3.2.1.5+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"python-wxtools", reference:"2.6.3.2.1.5+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"python-wxversion", reference:"2.6.3.2.1.5+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"wx-common", reference:"2.6.3.2.1.5+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"wx2.4-doc", reference:"2.4.5.1.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"wx2.4-examples", reference:"2.4.5.1.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"wx2.4-headers", reference:"2.4.5.1.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"wx2.4-i18n", reference:"2.4.5.1.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"wx2.6-doc", reference:"2.6.3.2.1.5+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"wx2.6-examples", reference:"2.6.3.2.1.5+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"wx2.6-headers", reference:"2.6.3.2.1.5+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"wx2.6-i18n", reference:"2.6.3.2.1.5+etch1")) flag++;
if (deb_check(release:"5.0", prefix:"libwxbase2.6-0", reference:"2.6.3.2.2-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libwxbase2.6-dbg", reference:"2.6.3.2.2-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libwxbase2.6-dev", reference:"2.6.3.2.2-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libwxbase2.8-0", reference:"2.8.7.1-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libwxbase2.8-dbg", reference:"2.8.7.1-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libwxbase2.8-dev", reference:"2.8.7.1-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libwxgtk2.6-0", reference:"2.6.3.2.2-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libwxgtk2.6-dbg", reference:"2.6.3.2.2-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libwxgtk2.6-dev", reference:"2.6.3.2.2-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libwxgtk2.8-0", reference:"2.8.7.1-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libwxgtk2.8-dbg", reference:"2.8.7.1-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libwxgtk2.8-dev", reference:"2.8.7.1-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"python-wxgtk2.6", reference:"2.6.3.2.2-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"python-wxgtk2.6-dbg", reference:"2.6.3.2.2-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"python-wxgtk2.8", reference:"2.8.7.1-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"python-wxgtk2.8-dbg", reference:"2.8.7.1-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"python-wxtools", reference:"2.6.3.2.2-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"python-wxversion", reference:"2.6.3.2.2-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wx-common", reference:"2.6.3.2.2-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wx2.6-doc", reference:"2.6.3.2.2-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wx2.6-examples", reference:"2.6.3.2.2-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wx2.6-headers", reference:"2.6.3.2.2-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wx2.6-i18n", reference:"2.6.3.2.2-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wx2.8-doc", reference:"2.8.7.1-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wx2.8-examples", reference:"2.8.7.1-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wx2.8-headers", reference:"2.8.7.1-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wx2.8-i18n", reference:"2.8.7.1-1.1+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
