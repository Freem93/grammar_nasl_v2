#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-638. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16156);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/18 00:15:57 $");

  script_cve_id("CVE-2004-0560", "CVE-2004-0561");
  script_osvdb_id(12912, 12913, 55703);
  script_xref(name:"DSA", value:"638");

  script_name(english:"Debian DSA-638-1 : gopher - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"'jaguar' has discovered two security relevant problems in gopherd, the
Gopher server in Debian which is part of the gopher package. The
Common Vulnerabilities and Exposures project identifies the following
vulnerabilities :

  - CAN-2004-0560
    An integer overflow can happen when posting content of a
    specially calculated size.

  - CAN-2004-0561

    A format string vulnerability has been found in the log
    routine."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-638"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gopherd package.

For the stable distribution (woody) these problems have been fixed in
version 3.0.3woody2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gopher");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/07/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"gopher", reference:"3.0.3woody2")) flag++;
if (deb_check(release:"3.0", prefix:"gopherd", reference:"3.0.3woody2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
