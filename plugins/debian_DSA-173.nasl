#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-173. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15010);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/17 23:49:56 $");

  script_cve_id("CVE-2002-1196");
  script_xref(name:"DSA", value:"173");

  script_name(english:"Debian DSA-173-1 : bugzilla - privilege escalation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The developers of Bugzilla, a web-based bug tracking system,
discovered a problem in the handling of more than 47 groups. When a
new product is added to an installation with 47 groups or more and
'usebuggroups' is enabled, the new group will be assigned a groupset
bit using Perl math that is not exact beyond 248. This results in the
new group being defined with a 'bit' that has several bits set. As
users are given access to the new group, those users will also gain
access to spurious lower group privileges. Also, group bits were not
always reused when groups were deleted."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-173"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bugzilla package.

This problem has been fixed in version 2.14.2-0woody2 for the current
stable distribution (woody) and will soon be fixed in the unstable
distribution (sid). The old stable distribution (potato) doesn't
contain a bugzilla package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bugzilla");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
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
if (deb_check(release:"3.0", prefix:"bugzilla", reference:"2.14.2-0woody2")) flag++;
if (deb_check(release:"3.0", prefix:"bugzilla-doc", reference:"2.14.2-0woody2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
