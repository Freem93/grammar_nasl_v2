#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2748. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69523);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/16 15:43:09 $");

  script_cve_id("CVE-2013-1438");
  script_bugtraq_id(62060);
  script_xref(name:"DSA", value:"2748");

  script_name(english:"Debian DSA-2748-1 : exactimage - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several denial-of-service vulnerabilities were discovered in the dcraw
code base, a program for procesing raw format images from digital
cameras. This update corrects them in the copy that is embedded in the
exactimage package."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=721236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/exactimage"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/exactimage"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2748"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the exactimage packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 0.8.1-3+deb6u2.

For the stable distribution (wheezy), this problem has been fixed in
version 0.8.5-5+deb7u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exactimage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"exactimage", reference:"0.8.1-3+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"exactimage-dbg", reference:"0.8.1-3+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"exactimage-perl", reference:"0.8.1-3+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libexactimage-perl", reference:"0.8.1-3+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"php5-exactimage", reference:"0.8.1-3+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"python-exactimage", reference:"0.8.1-3+deb6u2")) flag++;
if (deb_check(release:"7.0", prefix:"edisplay", reference:"0.8.5-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"exactimage", reference:"0.8.5-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"exactimage-dbg", reference:"0.8.5-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libexactimage-perl", reference:"0.8.5-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"php5-exactimage", reference:"0.8.5-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"python-exactimage", reference:"0.8.5-5+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
