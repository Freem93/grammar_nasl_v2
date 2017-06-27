#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2210. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53260);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2011-0191", "CVE-2011-0192", "CVE-2011-1167");
  script_bugtraq_id(46657, 46658, 46951);
  script_xref(name:"DSA", value:"2210");

  script_name(english:"Debian DSA-2210-1 : tiff - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in the TIFF manipulation and
conversion library :

  - CVE-2011-0191
    A buffer overflow allows to execute arbitrary code or
    cause a denial of service via a crafted TIFF image with
    JPEG encoding. This issue affects the Debian 5.0 Lenny
    package only.

  - CVE-2011-0192
    A buffer overflow allows to execute arbitrary code or
    cause a denial of service via a crafted TIFF Internet
    Fax image file that has been compressed using CCITT
    Group 4 encoding.

  - CVE-2011-1167
    Heap-based buffer overflow in the thunder (aka
    ThunderScan) decoder allows to execute arbitrary code
    via a TIFF file that has an unexpected BitsPerSample
    value."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=619614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1167"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/tiff"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2210"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the tiff packages.

For the oldstable distribution (lenny), these problems have been fixed
in version 3.8.2-11.4.

For the stable distribution (squeeze), these problems have been fixed
in version 3.9.4-5+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/04");
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
if (deb_check(release:"5.0", prefix:"tiff", reference:"3.8.2-11.4")) flag++;
if (deb_check(release:"6.0", prefix:"libtiff-doc", reference:"3.9.4-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libtiff-opengl", reference:"3.9.4-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libtiff-tools", reference:"3.9.4-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libtiff4", reference:"3.9.4-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libtiff4-dev", reference:"3.9.4-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libtiffxx0c2", reference:"3.9.4-5+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
