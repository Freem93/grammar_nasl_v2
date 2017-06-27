#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-813. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19709);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/05/18 00:15:59 $");

  script_cve_id("CVE-2005-2369", "CVE-2005-2370", "CVE-2005-2448");
  script_bugtraq_id(14415);
  script_osvdb_id(18125, 18126, 18127);
  script_xref(name:"DSA", value:"813");

  script_name(english:"Debian DSA-813-1 : centericq - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several problems have been discovered in libgadu which is also part of
centericq, a text-mode multi-protocol instant messenger client. The
Common Vulnerabilities and Exposures project identifies the following
problems :

  - CAN-2005-2369
    Multiple integer signedness errors may allow remote
    attackers to cause a denial of service or execute
    arbitrary code.

  - CAN-2005-2370

    Memory alignment errors may allows remote attackers to
    cause a denial of service on certain architectures such
    as sparc.

  - CAN-2005-2448

    Several endianess errors may allow remote attackers to
    cause a denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-813"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the centericq package.

The old stable distribution (woody) is not affected by these problems.

For the stable distribution (sarge) these problems have been fixed in
version 4.20.0-1sarge2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:centericq");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/17");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/21");
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
if (deb_check(release:"3.1", prefix:"centericq", reference:"4.20.0-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"centericq-common", reference:"4.20.0-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"centericq-fribidi", reference:"4.20.0-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"centericq-utf8", reference:"4.20.0-1sarge2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
