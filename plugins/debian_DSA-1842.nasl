#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1842. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44707);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/06 20:12:52 $");

  script_cve_id("CVE-2009-1720", "CVE-2009-1721", "CVE-2009-1722");
  script_osvdb_id(56707, 56708);
  script_xref(name:"DSA", value:"1842");

  script_name(english:"Debian DSA-1842-1 : openexr - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the OpenEXR image
library, which can lead to the execution of arbitrary code. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2009-1720
    Drew Yao discovered integer overflows in the preview and
    compression code.

  - CVE-2009-1721
    Drew Yao discovered that an uninitialised pointer could
    be freed in the decompression code.

  - CVE-2009-1722
    A buffer overflow was discovered in the compression
    code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1720"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1842"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openexr packages.

For the old stable distribution (etch), these problems have been fixed
in version 1.2.2-4.3+etch2.

For the stable distribution (lenny), these problems have been fixed in
version 1.6.1-3+lenny3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(16, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openexr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libopenexr-dev", reference:"1.2.2-4.3+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libopenexr2c2a", reference:"1.2.2-4.3+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"openexr", reference:"1.2.2-4.3+etch2")) flag++;
if (deb_check(release:"5.0", prefix:"libopenexr-dev", reference:"1.6.1-3+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"libopenexr6", reference:"1.6.1-3+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openexr", reference:"1.6.1-3+lenny3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
