#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2412. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58012);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:31:57 $");

  script_cve_id("CVE-2012-0444");
  script_bugtraq_id(51753);
  script_osvdb_id(78739);
  script_xref(name:"DSA", value:"2412");

  script_name(english:"Debian DSA-2412-1 : libvorbis - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that a heap overflow in the Vorbis audio compression
library could lead to the execution of arbitrary code if a malformed
Ogg Vorbis file is processed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/libvorbis"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2412"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libvorbis packages.

For the stable distribution (squeeze), this problem has been fixed in
version 1.3.1-1+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvorbis");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libvorbis-dbg", reference:"1.3.1-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libvorbis-dev", reference:"1.3.1-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libvorbis0a", reference:"1.3.1-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libvorbisenc2", reference:"1.3.1-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libvorbisfile3", reference:"1.3.1-1+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
