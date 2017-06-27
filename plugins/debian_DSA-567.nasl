#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-567. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15665);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2013/05/18 00:11:36 $");

  script_cve_id("CVE-2004-0803", "CVE-2004-0804", "CVE-2004-0886");
  script_bugtraq_id(11406);
  script_osvdb_id(10750, 10751, 10909);
  script_xref(name:"CERT", value:"555304");
  script_xref(name:"CERT", value:"687568");
  script_xref(name:"DSA", value:"567");

  script_name(english:"Debian DSA-567-1 : tiff - heap overflows");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several problems have been discovered in libtiff, the Tag Image File
Format library for processing TIFF graphics files. An attacker could
prepare a specially crafted TIFF graphic that would cause the client
to execute arbitrary code or crash. The Common Vulnerabilities and
Exposures Project has identified the following problems :

  - CAN-2004-0803
    Chris Evans discovered several problems in the RLE (run
    length encoding) decoders that could lead to arbitrary
    code execution.

  - CAN-2004-0804

    Matthias Clasen discovered a division by zero through an
    integer overflow.

  - CAN-2004-0886

    Dmitry V. Levin discovered several integer overflows
    that caused malloc issues which can result to either
    plain crash or memory corruption."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-567"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libtiff package.

For the stable distribution (woody) these problems have been fixed in
version 3.5.5-6woody1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/14");
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
if (deb_check(release:"3.0", prefix:"libtiff-tools", reference:"3.5.5-6woody1")) flag++;
if (deb_check(release:"3.0", prefix:"libtiff3g", reference:"3.5.5-6woody1")) flag++;
if (deb_check(release:"3.0", prefix:"libtiff3g-dev", reference:"3.5.5-6woody1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
