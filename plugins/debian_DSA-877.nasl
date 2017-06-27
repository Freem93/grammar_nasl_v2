#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-877. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22743);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2014/08/13 14:23:42 $");

  script_cve_id("CVE-2005-3123", "CVE-2005-3424", "CVE-2005-3425");
  script_osvdb_id(20359, 20360, 20723);
  script_xref(name:"DSA", value:"877");

  script_name(english:"Debian DSA-877-1 : gnump3d - XSS, directory traversal");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Steve Kemp discovered two vulnerabilities in gnump3d, a streaming
server for MP3 and OGG files. The Common Vulnerabilities and Exposures
Project identifies the following problems :

  - CVE-2005-3122
    The 404 error page does not strip malicious JavaScript
    content from the resulting page, which would be executed
    in the victims browser.

  - CVE-2005-3123
    By using specially crafting URLs it is possible to read
    arbitrary files to which the user of the streaming
    server has access to."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-877"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gnump3d package.

The old stable distribution (woody) does not contain a gnump3d
package.

For the stable distribution (sarge) these problems have been fixed in
version 2.9.3-1sarge2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnump3d");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"gnump3d", reference:"2.9.3-1sarge2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
