#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-713. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18115);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/18 00:15:58 $");

  script_cve_id("CVE-2005-1108", "CVE-2005-1109");
  script_osvdb_id(15502, 15503);
  script_xref(name:"DSA", value:"713");

  script_name(english:"Debian DSA-713-1 : junkbuster - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several bugs have been found in junkbuster, a HTTP proxy and filter.
The Common Vulnerabilities and Exposures project identifies the
following vulnerabilities :

  - CAN-2005-1108
    James Ranson discovered that an attacker can modify the
    referrer setting with a carefully crafted URL by
    accidentally overwriting a global variable.

  - CAN-2005-1109

    Tavis Ormandy from the Gentoo Security Team discovered
    several heap corruptions due to inconsistent use of an
    internal function that can crash the daemon or possibly
    lead to the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-713"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the junkbuster package.

For the stable distribution (woody) these problems have been fixed in
version 2.0.2-0.2woody1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:junkbuster");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/22");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/13");
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
if (deb_check(release:"3.0", prefix:"junkbuster", reference:"2.0.2-0.2woody1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
