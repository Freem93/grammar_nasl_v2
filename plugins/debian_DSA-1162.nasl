#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1162. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22704);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/17 23:41:26 $");

  script_cve_id("CVE-2006-4197");
  script_bugtraq_id(19508);
  script_osvdb_id(27944, 27945);
  script_xref(name:"DSA", value:"1162");

  script_name(english:"Debian DSA-1162-1 : libmusicbrainz-2.0 - buffer overflows");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Luigi Auriemma discovered several buffer overflows in libmusicbrainz,
a CD index library, that allow remote attackers to cause a denial of
service or execute arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=383030"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1162"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libmusicbrainz packages.

For the stable distribution (sarge) these problems have been fixed in
version 2.0.2-10sarge1 and 2.1.1-3sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmusicbrainz-2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmusicbrainz-2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libmusicbrainz2", reference:"2.0.2-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libmusicbrainz2-dev", reference:"2.0.2-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libmusicbrainz4", reference:"2.1.1-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libmusicbrainz4-dev", reference:"2.1.1-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"python-musicbrainz", reference:"2.0.2-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"python2.1-musicbrainz", reference:"2.0.2-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"python2.2-musicbrainz", reference:"2.0.2-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"python2.3-musicbrainz", reference:"2.0.2-10sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
