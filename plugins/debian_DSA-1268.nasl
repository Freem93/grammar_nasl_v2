#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1268. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24835);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-0002", "CVE-2007-1466");
  script_osvdb_id(33315);
  script_xref(name:"DSA", value:"1268");

  script_name(english:"Debian DSA-1268-1 : libwpd - integer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"iDefense reported several integer overflow bugs in libwpd, a library
for handling WordPerfect documents. Attackers were able to exploit
these with carefully crafted Word Perfect files that could cause an
application linked with libwpd to crash or possibly execute arbitrary
code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1268"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libwpd package.

For the stable distribution (sarge) these problems have been fixed in
version 0.8.1-1sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libwpd-stream8", reference:"0.8.1-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libwpd-tools", reference:"0.8.1-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libwpd8", reference:"0.8.1-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libwpd8-dev", reference:"0.8.1-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libwpd8-doc", reference:"0.8.1-1sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
