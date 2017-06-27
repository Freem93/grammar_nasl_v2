#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2698. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66916);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/07 14:54:25 $");

  script_cve_id("CVE-2013-1960", "CVE-2013-1961");
  script_bugtraq_id(59607, 59609);
  script_osvdb_id(92986, 92987);
  script_xref(name:"DSA", value:"2698");

  script_name(english:"Debian DSA-2698-1 : tiff - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple issues were discovered in the TIFF tools, a set of utilities
for TIFF image file manipulation and conversion.

  - CVE-2013-1960
    Emmanuel Bouillon discovered a heap-based buffer
    overflow in the tp_process_jpeg_strip function in the
    tiff2pdf tool. This could potentially lead to a crash or
    arbitrary code execution.

  - CVE-2013-1961
    Emmanuel Bouillon discovered many stack-based buffer
    overflows in the TIFF tools. These issues could
    potentially lead to a crash or arbitrary code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=706674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=706675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1961"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/tiff"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/tiff"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2698"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the tiff packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 3.9.4-5+squeeze9.

For the stable distribution (wheezy), these problems have been fixed
in version 4.0.2-6+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/19");
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
if (deb_check(release:"6.0", prefix:"libtiff-doc", reference:"3.9.4-5+squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"libtiff-opengl", reference:"3.9.4-5+squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"libtiff-tools", reference:"3.9.4-5+squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"libtiff4", reference:"3.9.4-5+squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"libtiff4-dev", reference:"3.9.4-5+squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"libtiffxx0c2", reference:"3.9.4-5+squeeze9")) flag++;
if (deb_check(release:"7.0", prefix:"libtiff-doc", reference:"4.0.2-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libtiff-opengl", reference:"4.0.2-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libtiff-tools", reference:"4.0.2-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libtiff5", reference:"4.0.2-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libtiff5-alt-dev", reference:"4.0.2-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libtiff5-dev", reference:"4.0.2-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libtiffxx5", reference:"4.0.2-6+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
