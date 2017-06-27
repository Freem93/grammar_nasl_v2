#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2953. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74375);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/16 15:48:47 $");

  script_cve_id("CVE-2014-3864", "CVE-2014-3865");
  script_bugtraq_id(67725, 67727);
  script_xref(name:"DSA", value:"2953");

  script_name(english:"Debian DSA-2953-1 : dpkg - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in dpkg that allow file
modification through path traversal when unpacking source packages
with specially crafted patch files.

This update had been scheduled before the end of security support for
the oldstable distribution (squeeze), hence an exception has been made
and was released through the security archive. However, no further
updates should be expected."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=746498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=749183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/dpkg"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/dpkg"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2953"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the dpkg packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 1.15.11.

For the stable distribution (wheezy), these problems have been fixed
in version 1.16.15."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dpkg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"dpkg", reference:"1.15.11")) flag++;
if (deb_check(release:"6.0", prefix:"dpkg-dev", reference:"1.15.11")) flag++;
if (deb_check(release:"6.0", prefix:"dselect", reference:"1.15.11")) flag++;
if (deb_check(release:"6.0", prefix:"libdpkg-dev", reference:"1.15.11")) flag++;
if (deb_check(release:"6.0", prefix:"libdpkg-perl", reference:"1.15.11")) flag++;
if (deb_check(release:"7.0", prefix:"dpkg", reference:"1.16.15")) flag++;
if (deb_check(release:"7.0", prefix:"dpkg-dev", reference:"1.16.15")) flag++;
if (deb_check(release:"7.0", prefix:"dselect", reference:"1.16.15")) flag++;
if (deb_check(release:"7.0", prefix:"libdpkg-dev", reference:"1.16.15")) flag++;
if (deb_check(release:"7.0", prefix:"libdpkg-perl", reference:"1.16.15")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
