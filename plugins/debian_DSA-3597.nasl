#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3597. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91506);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/12/06 20:25:09 $");

  script_cve_id("CVE-2012-6702", "CVE-2016-5300");
  script_osvdb_id(80892, 139342);
  script_xref(name:"DSA", value:"3597");

  script_name(english:"Debian DSA-3597-1 : expat - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two related issues have been discovered in Expat, a C library for
parsing XML.

  - CVE-2012-6702
    It was introduced when CVE-2012-0876 was addressed.
    Stefan Sorensen discovered that the use of the function
    XML_Parse() seeds the random number generator generating
    repeated outputs for rand() calls.

  - CVE-2016-5300
    It is the product of an incomplete solution for
    CVE-2012-0876. The parser poorly seeds the random number
    generator allowing an attacker to cause a denial of
    service (CPU consumption) via an XML file with crafted
    identifiers.

You might need to manually restart programs and services using expat
libraries."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-6702"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/expat"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3597"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the expat packages.

For the stable distribution (jessie), these problems have been fixed
in version 2.1.0-6+deb8u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:expat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/08");
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
if (deb_check(release:"8.0", prefix:"expat", reference:"2.1.0-6+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"lib64expat1", reference:"2.1.0-6+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"lib64expat1-dev", reference:"2.1.0-6+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libexpat1", reference:"2.1.0-6+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libexpat1-dev", reference:"2.1.0-6+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libexpat1-udeb", reference:"2.1.0-6+deb8u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
