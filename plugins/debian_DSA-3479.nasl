#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3479. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88865);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/10/10 14:14:52 $");

  script_cve_id("CVE-2016-1521", "CVE-2016-1522", "CVE-2016-1523", "CVE-2016-1526");
  script_xref(name:"DSA", value:"3479");

  script_name(english:"Debian DSA-3479-1 : graphite2 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been found in the Graphite font
rendering engine which might result in denial of service or the
execution of arbitrary code if a malformed font file is processed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/graphite2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/graphite2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3479"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the graphite2 packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 1.3.5-1~deb7u1.

For the stable distribution (jessie), these problems have been fixed
in version 1.3.5-1~deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphite2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/22");
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
if (deb_check(release:"7.0", prefix:"libgraphite2-2.0.0", reference:"1.3.5-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgraphite2-2.0.0-dbg", reference:"1.3.5-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgraphite2-dev", reference:"1.3.5-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgraphite2-doc", reference:"1.3.5-1~deb7u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgraphite2-3", reference:"1.3.5-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgraphite2-3-dbg", reference:"1.3.5-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgraphite2-dev", reference:"1.3.5-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgraphite2-doc", reference:"1.3.5-1~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
