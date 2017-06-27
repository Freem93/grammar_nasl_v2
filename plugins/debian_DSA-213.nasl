#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-213. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15050);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/05/17 23:58:35 $");

  script_cve_id("CVE-2002-1363");
  script_bugtraq_id(6431);
  script_xref(name:"DSA", value:"213");

  script_name(english:"Debian DSA-213-1 : libpng - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Glenn Randers-Pehrson discovered a problem in connection with 16-bit
samples from libpng, an interface for reading and writing PNG
(Portable Network Graphics) format files. The starting offsets for the
loops are calculated incorrectly which causes a buffer overrun beyond
the beginning of the row buffer."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-213"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libpng packages.

For the current stable distribution (woody) this problem has been
fixed in version 1.0.12-3.woody.3 for libpng and in version
1.2.1-1.1.woody.3 for libpng3.

For the old stable distribution (potato) this problem has been fixed
in version 1.0.5-1.1 for libpng. There are no other libpng packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpng3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"libpng2", reference:"1.0.5-1.1")) flag++;
if (deb_check(release:"2.2", prefix:"libpng2-dev", reference:"1.0.5-1.1")) flag++;
if (deb_check(release:"3.0", prefix:"libpng-dev", reference:"1.2.1-1.1.woody.3")) flag++;
if (deb_check(release:"3.0", prefix:"libpng2", reference:"1.0.12-3.woody.3")) flag++;
if (deb_check(release:"3.0", prefix:"libpng2-dev", reference:"1.0.12-3.woody.3")) flag++;
if (deb_check(release:"3.0", prefix:"libpng3", reference:"1.2.1-1.1.woody.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
