#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3612. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91923);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/10 14:14:53 $");

  script_cve_id("CVE-2016-4994");
  script_xref(name:"DSA", value:"3612");

  script_name(english:"Debian DSA-3612-1 : gimp - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Shmuel H discovered that GIMP, the GNU Image Manipulation Program, is
prone to a use-after-free vulnerability in the channel and layer
properties parsing process when loading a XCF file. An attacker can
take advantage of this flaw to potentially execute arbitrary code with
the privileges of the user running GIMP if a specially crafted XCF
file is processed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=828179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/gimp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3612"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gimp packages.

For the stable distribution (jessie), this problem has been fixed in
version 2.8.14-1+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gimp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"gimp", reference:"2.8.14-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gimp-data", reference:"2.8.14-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gimp-dbg", reference:"2.8.14-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgimp2.0", reference:"2.8.14-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgimp2.0-dev", reference:"2.8.14-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgimp2.0-doc", reference:"2.8.14-1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
