#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-901. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22767);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/18 00:19:43 $");

  script_cve_id("CVE-2005-3349", "CVE-2005-3355");
  script_osvdb_id(20939, 20940);
  script_xref(name:"DSA", value:"901");

  script_name(english:"Debian DSA-901-1 : gnump3d - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in gnump3d, a streaming
server for MP3 and OGG files. The Common Vulnerabilities and Exposures
Project identifies the following problems :

  - CVE-2005-3349
    Ludwig Nussel discovered several temporary files that
    are created with predictable filenames in an insecure
    fashion and allows local attackers to craft symlink
    attacks.

  - CVE-2005-3355
    Ludwig Nussel discovered that the theme parameter to
    HTTP requests may be used for path traversal."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-901"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gnump3 package.

The old stable distribution (woody) does not contain a gnump3d
package.

For the stable distribution (sarge) these problems have been fixed in
version 2.9.3-1sarge3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnump3d");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/17");
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
if (deb_check(release:"3.1", prefix:"gnump3d", reference:"2.9.3-1sarge3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
