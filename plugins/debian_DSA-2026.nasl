#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2026. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45407);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2013/11/14 14:27:59 $");

  script_cve_id("CVE-2009-4274");
  script_bugtraq_id(38164);
  script_osvdb_id(62270);
  script_xref(name:"DSA", value:"2026");

  script_name(english:"Debian DSA-2026-1 : netpbm-free - stack-based buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Marc Schoenefeld discovered a stack-based buffer overflow in the XPM
reader implementation in netpbm-free, a suite of image manipulation
utilities. An attacker could cause a denial of service (application
crash) or possibly execute arbitrary code via an XPM image file that
contains a crafted header field associated with a large color index
value."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=569060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2026"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the netpbm-free package.

For the stable distribution (lenny), this problem has been fixed in
version 2:10.0-12+lenny1.

Due to a problem with the archive system it is not possible to release
all architectures. The missing architectures will be installed into
the archive once they become available."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:netpbm-free");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"libnetpbm10", reference:"2:10.0-12+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libnetpbm10-dev", reference:"2:10.0-12+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libnetpbm9", reference:"2:10.0-12+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libnetpbm9-dev", reference:"2:10.0-12+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"netpbm", reference:"2:10.0-12+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
