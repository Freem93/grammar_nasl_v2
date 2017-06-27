#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3856. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100278);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/24 13:36:52 $");

  script_cve_id("CVE-2017-7178", "CVE-2017-9031");
  script_osvdb_id(152984, 157684);
  script_xref(name:"DSA", value:"3856");

  script_name(english:"Debian DSA-3856-1 : deluge - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities have been discovered in the web interface of the
Deluge BitTorrent client (directory traversal and cross-site request
forgery)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/deluge"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2017/dsa-3856"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the deluge packages.

For the stable distribution (jessie), these problems have been fixed
in version 1.3.10-3+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:deluge");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/19");
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
if (deb_check(release:"8.0", prefix:"deluge", reference:"1.3.10-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"deluge-common", reference:"1.3.10-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"deluge-console", reference:"1.3.10-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"deluge-gtk", reference:"1.3.10-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"deluge-torrent", reference:"1.3.10-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"deluge-web", reference:"1.3.10-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"deluge-webui", reference:"1.3.10-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"deluged", reference:"1.3.10-3+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
