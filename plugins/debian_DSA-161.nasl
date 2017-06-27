#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-161. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14998);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/17 23:49:54 $");

  script_cve_id("CVE-2002-1115", "CVE-2002-1116");
  script_osvdb_id(6206, 6207, 6208, 6209, 6210);
  script_xref(name:"DSA", value:"161");

  script_name(english:"Debian DSA-161-1 : mantis - privilege escalation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A problem with user privileges has been discovered in the Mantis
package, a PHP based bug tracking system. The Mantis system didn't
check whether a user is permitted to view a bug, but displays it right
away if the user entered a valid bug id.

Another bug in Mantis caused the 'View Bugs' page to list bugs from
both public and private projects when no projects are accessible to
the current user.

These problems have been fixed in version 0.17.1-2.5 for the current
stable distribution (woody) and in version 0.17.5-2 for the unstable
distribution (sid). The old stable distribution (potato) is not
affected, since it doesn't contain the mantis package.

Additional information :

  - Mantis Advisory/2002-06
  - Mantis Advisory/2002-07"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://mantisbt.sourceforge.net/advisories/2002/2002-06.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://mantisbt.sourceforge.net/advisories/2002/2002-07.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-161"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the mantis packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mantis");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/08/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"mantis", reference:"0.17.1-2.5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
