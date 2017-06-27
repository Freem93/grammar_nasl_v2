#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-863. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20018);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/26 16:04:30 $");

  script_cve_id("CVE-2005-2967");
  script_osvdb_id(19892);
  script_xref(name:"DSA", value:"863");

  script_name(english:"Debian DSA-863-1 : xine-lib - format string vulnerability");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ulf Harnhammar from the Debian Security Audit Project discovered a
format string vulnerability in the CDDB processing component of
xine-lib, the xine video/media player library, that could lead to the
execution of arbitrary code caused by a malicious CDDB entry."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=332919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-863"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libxine0 and libxine1 packages.

For the old stable distribution (woody) this problem has been fixed in
version 0.9.8-2woody4.

For the stable distribution (sarge) this problem has been fixed in
version 1.0.1-1sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xine-lib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/19");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"libxine-dev", reference:"0.9.8-2woody4")) flag++;
if (deb_check(release:"3.0", prefix:"libxine0", reference:"0.9.8-2woody4")) flag++;
if (deb_check(release:"3.1", prefix:"libxine-dev", reference:"1.0.1-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libxine1", reference:"1.0.1-1sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
