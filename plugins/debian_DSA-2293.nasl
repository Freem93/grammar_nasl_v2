#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2293. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55841);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2011-2895");
  script_bugtraq_id(49124);
  script_osvdb_id(74927);
  script_xref(name:"DSA", value:"2293");

  script_name(english:"Debian DSA-2293-1 : libxfont - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tomas Hoger found a buffer overflow in the X.Org libXfont library,
which may allow for a local privilege escalation through crafted font
files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/libxfont"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2293"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libxfont packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.3.3-2.

For the stable distribution (squeeze), this problem has been fixed in
version 1.4.1-3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxfont");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/15");
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
if (deb_check(release:"5.0", prefix:"libxfont", reference:"1.3.3-2")) flag++;
if (deb_check(release:"6.0", prefix:"libxfont-dev", reference:"1.4.1-3")) flag++;
if (deb_check(release:"6.0", prefix:"libxfont1", reference:"1.4.1-3")) flag++;
if (deb_check(release:"6.0", prefix:"libxfont1-dbg", reference:"1.4.1-3")) flag++;
if (deb_check(release:"6.0", prefix:"libxfont1-udeb", reference:"1.4.1-3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
