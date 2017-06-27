#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2263. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55164);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/02/16 15:31:55 $");

  script_bugtraq_id(48195);
  script_xref(name:"DSA", value:"2263");

  script_name(english:"Debian DSA-2263-2 : movabletype-opensource - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Movable Type, a weblog publishing system,
contains several security vulnerabilities :

A remote attacker could execute arbitrary code in a logged-in users'
web browser.

A remote attacker could read or modify the contents in the system
under certain circumstances."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=627936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/movabletype-opensource"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2263"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the movabletype-opensource packages.

For the oldstable distribution (lenny), these problems have been fixed
in version 4.2.3-1+lenny3.

For the stable distribution (squeeze), these problems have been fixed
in version 4.3.5+dfsg-2+squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:movabletype-opensource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"movabletype-opensource", reference:"4.2.3-1+lenny3")) flag++;
if (deb_check(release:"6.0", prefix:"movabletype-opensource", reference:"4.3.5+dfsg-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"movabletype-plugin-core", reference:"4.3.5+dfsg-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"movabletype-plugin-zemanta", reference:"4.3.5+dfsg-2+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
