#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2808. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(71180);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/09/30 13:55:33 $");

  script_cve_id("CVE-2013-1447", "CVE-2013-6045", "CVE-2013-6052", "CVE-2013-6054");
  script_bugtraq_id(64109, 64113, 64118, 64142);
  script_osvdb_id(100628, 100629, 100630, 100631, 100632, 100633, 100634, 100635, 100636, 100637, 100638, 100639, 100640, 100641, 100642, 100643, 100644, 100645, 100646);
  script_xref(name:"DSA", value:"2808");

  script_name(english:"Debian DSA-2808-1 : openjpeg - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in OpenJPEG, a JPEG 2000
image library, that may lead to denial of service (CVE-2013-1447 ) via
application crash or high memory consumption, possible code execution
through heap buffer overflows (CVE-2013-6045 ), information disclosure
(CVE-2013-6052 ), or yet another heap buffer overflow that only
appears to affect OpenJPEG 1.3 (CVE-2013-6054 )."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1447"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6045"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/openjpeg"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/openjpeg"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2808"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openjpeg packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 1.3+dfsg-4+squeeze2.

For the stable distribution (wheezy), these problems have been fixed
in version 1.3+dfsg-4.7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjpeg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libopenjpeg-dev", reference:"1.3+dfsg-4+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libopenjpeg2", reference:"1.3+dfsg-4+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libopenjpeg2-dbg", reference:"1.3+dfsg-4+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openjpeg-tools", reference:"1.3+dfsg-4+squeeze2")) flag++;
if (deb_check(release:"7.0", prefix:"libopenjpeg-dev", reference:"1.3+dfsg-4.7")) flag++;
if (deb_check(release:"7.0", prefix:"libopenjpeg2", reference:"1.3+dfsg-4.7")) flag++;
if (deb_check(release:"7.0", prefix:"libopenjpeg2-dbg", reference:"1.3+dfsg-4.7")) flag++;
if (deb_check(release:"7.0", prefix:"openjpeg-tools", reference:"1.3+dfsg-4.7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
