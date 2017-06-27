#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1798. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38725);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/05/20 10:48:33 $");

  script_cve_id("CVE-2009-1194");
  script_bugtraq_id(34870);
  script_osvdb_id(54279);
  script_xref(name:"DSA", value:"1798");

  script_name(english:"Debian DSA-1798-1 : pango1.0 - integer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Will Drewry discovered that pango, a system for layout and rendering
of internationalized text, is prone to an integer overflow via long
glyphstrings. This could cause the execution of arbitrary code when
displaying crafted data through an application using the pango
library."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=527474"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1798"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the pango1.0 packages.

For the oldstable distribution (etch), this problem has been fixed in
version 1.14.8-5+etch1.

For the stable distribution (lenny), this problem has been fixed in
version 1.20.5-3+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pango1.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libpango1.0-0", reference:"1.14.8-5+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libpango1.0-0-dbg", reference:"1.14.8-5+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libpango1.0-common", reference:"1.14.8-5+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libpango1.0-dev", reference:"1.14.8-5+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libpango1.0-doc", reference:"1.14.8-5+etch1")) flag++;
if (deb_check(release:"5.0", prefix:"libpango1.0-0", reference:"1.20.5-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libpango1.0-0-dbg", reference:"1.20.5-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libpango1.0-common", reference:"1.20.5-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libpango1.0-dev", reference:"1.20.5-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libpango1.0-doc", reference:"1.20.5-3+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
