#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-672. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16346);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/26 15:53:38 $");

  script_cve_id("CVE-2005-0076");
  script_osvdb_id(13672);
  script_xref(name:"DSA", value:"672");

  script_name(english:"Debian DSA-672-1 : xview - buffer overflows");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Erik Sjolund discovered that programs linked against xview are
vulnerable to a number of buffer overflows in the XView library. When
the overflow is triggered in a program which is installed setuid root
a malicious user could perhaps execute arbitrary code as privileged
user."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-672"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xview packages.

For the stable distribution (woody) these problems have been fixed in
version 3.2p1.4-16woody2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xview");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"olvwm", reference:"4.4.3.2p1.4-16woody2")) flag++;
if (deb_check(release:"3.0", prefix:"olwm", reference:"3.2p1.4-16woody2")) flag++;
if (deb_check(release:"3.0", prefix:"xview-clients", reference:"3.2p1.4-16woody2")) flag++;
if (deb_check(release:"3.0", prefix:"xview-examples", reference:"3.2p1.4-16woody2")) flag++;
if (deb_check(release:"3.0", prefix:"xviewg", reference:"3.2p1.4-16woody2")) flag++;
if (deb_check(release:"3.0", prefix:"xviewg-dev", reference:"3.2p1.4-16woody2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");