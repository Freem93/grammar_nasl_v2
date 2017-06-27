#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3399. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86921);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/04/28 18:33:24 $");

  script_cve_id("CVE-2015-7981", "CVE-2015-8126");
  script_osvdb_id(129444, 130175);
  script_xref(name:"DSA", value:"3399");

  script_name(english:"Debian DSA-3399-1 : libpng - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the libpng PNG
library. The Common Vulnerabilities and Exposures project identifies
the following problems :

  - CVE-2015-7981
    Qixue Xiao discovered an out-of-bounds read
    vulnerability in the png_convert_to_rfc1123 function. A
    remote attacker can potentially take advantage of this
    flaw to cause disclosure of information from process
    memory.

  - CVE-2015-8126
    Multiple buffer overflows were discovered in the
    png_set_PLTE and png_get_PLTE functions. A remote
    attacker can take advantage of this flaw to cause a
    denial of service (application crash) via a small
    bit-depth value in an IHDR (image header) chunk in a PNG
    image."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=803078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=805113"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libpng"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libpng"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3399"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libpng packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 1.2.49-1+deb7u1.

For the stable distribution (jessie), these problems have been fixed
in version 1.2.50-2+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpng");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libpng12-0", reference:"1.2.49-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpng12-0-udeb", reference:"1.2.49-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpng12-dev", reference:"1.2.49-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpng3", reference:"1.2.49-1+deb7u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpng12-0", reference:"1.2.50-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpng12-0-udeb", reference:"1.2.50-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpng12-dev", reference:"1.2.50-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpng3", reference:"1.2.50-2+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
