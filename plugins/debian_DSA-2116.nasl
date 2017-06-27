#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2116. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49766);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/08/16 19:09:25 $");

  script_cve_id("CVE-2010-3311");
  script_bugtraq_id(43700, 43841, 43845);
  script_xref(name:"DSA", value:"2116");

  script_name(english:"Debian DSA-2116-1 : freetype - integer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Marc Schoenefeld has found an input stream position error in the way
the FreeType font rendering engine processed input file streams. If a
user loaded a specially crafted font file with an application linked
against FreeType and relevant font glyphs were subsequently rendered
with the X FreeType library (libXft), it could cause the application
to crash or, possibly execute arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2116"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the freetype packages.

After the upgrade, all running applications and services that use
libfreetype6 should be restarted. In most cases, logging out and in
again should be enough. The script checkrestart from the
debian-goodies package or lsof may help to find out which processes
are still using the old version of libfreetype6.

For the stable distribution (lenny), these problems have been fixed in
version 2.3.7-2+lenny4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freetype");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/06");
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
if (deb_check(release:"5.0", prefix:"freetype2-demos", reference:"2.3.7-2+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libfreetype6", reference:"2.3.7-2+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libfreetype6-dev", reference:"2.3.7-2+lenny4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
