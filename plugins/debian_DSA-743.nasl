#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-743. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18651);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/18 00:15:58 $");

  script_cve_id("CVE-2005-1545", "CVE-2005-1546");
  script_osvdb_id(16351, 16352);
  script_xref(name:"DSA", value:"743");

  script_name(english:"Debian DSA-743-1 : ht - buffer overflows, integer overflows");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several problems have been discovered in ht, a viewer, editor and
analyser for various executables, that may lead to the execution of
arbitrary code. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CAN-2005-1545
    Tavis Ormandy of the Gentoo Linux Security Team
    discovered an integer overflow in the ELF parser.

  - CAN-2005-1546

    The authors have discovered a buffer overflow in the PE
    parser."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-743"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ht package.

For the old stable distribution (woody) these problems have been fixed
in version 0.5.0-1woody4. For the HP Precision architecture, you are
advised not to use this package anymore since we cannot provide
updated packages as it doesn't compile anymore.

For the stable distribution (sarge) these problems have been fixed in
version 0.8.0-2sarge4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ht");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/08");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"ht", reference:"0.5.0-1woody4")) flag++;
if (deb_check(release:"3.1", prefix:"ht", reference:"0.8.0-2sarge4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
