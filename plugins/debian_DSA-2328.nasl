#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2328. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56624);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2011-3256");
  script_bugtraq_id(50155);
  script_osvdb_id(76324);
  script_xref(name:"DSA", value:"2328");

  script_name(english:"Debian DSA-2328-1 : freetype - missing input sanitising");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that missing input sanitising in Freetype's glyph
handling could lead to memory corruption, resulting in denial of
service or the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=646120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/freetype"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2328"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the freetype packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 2.3.7-2+lenny7.

For the stable distribution (squeeze), this problem has been fixed in
version 2.4.2-2.1+squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freetype");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"freetype", reference:"2.3.7-2+lenny7")) flag++;
if (deb_check(release:"6.0", prefix:"freetype2-demos", reference:"2.4.2-2.1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libfreetype6", reference:"2.4.2-2.1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libfreetype6-dev", reference:"2.4.2-2.1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libfreetype6-udeb", reference:"2.4.2-2.1+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
