#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-169. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15006);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/05/26 15:53:37 $");

  script_cve_id("CVE-2002-1195");
  script_osvdb_id(9226);
  script_xref(name:"DSA", value:"169");

  script_name(english:"Debian DSA-169-1 : htcheck - XSS");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ulf Harnhammar discovered a problem in ht://Check's PHP interface.
The PHP interface displays information unchecked which was gathered
from crawled external web servers. This could lead into a cross site
scripting attack if somebody has control over the server responses of
a remote web server which is crawled by ht://Check."
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=103184269605160
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=bugtraq&m=103184269605160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-169"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the htcheck package immediately.

This problem has been fixed in version 1.1-1.1 for the current stable
distribution (woody) and in version 1.1-1.2 for the unstable release
(sid). The old stable release (potato) does not contain the htcheck
package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:htcheck");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/09/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"htcheck", reference:"1.1-1.1")) flag++;
if (deb_check(release:"3.0", prefix:"htcheck-php", reference:"1.1-1.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
