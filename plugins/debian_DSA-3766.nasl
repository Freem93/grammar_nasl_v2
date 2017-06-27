#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3766. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96637);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/03/21 13:39:52 $");

  script_cve_id("CVE-2017-5522");
  script_osvdb_id(150652);
  script_xref(name:"DSA", value:"3766");

  script_name(english:"Debian DSA-3766-1 : mapserver - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that mapserver, a CGI-based framework for Internet
map services, was vulnerable to a stack-based overflow. This issue
allowed a remote user to crash the service, or potentially execute
arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/mapserver"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2017/dsa-3766"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mapserver packages.

For the stable distribution (jessie), this problem has been fixed in
version 6.4.1-5+deb8u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mapserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"cgi-mapserver", reference:"6.4.1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libmapscript-java", reference:"6.4.1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libmapscript-perl", reference:"6.4.1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libmapscript-ruby", reference:"6.4.1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libmapscript-ruby1.8", reference:"6.4.1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libmapscript-ruby1.9.1", reference:"6.4.1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libmapserver1", reference:"6.4.1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libmapserver1-dbg", reference:"6.4.1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libmapserver1-dev", reference:"6.4.1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"mapserver-bin", reference:"6.4.1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"mapserver-doc", reference:"6.4.1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"php5-mapscript", reference:"6.4.1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"python-mapscript", reference:"6.4.1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-mapscript", reference:"6.4.1-5+deb8u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
