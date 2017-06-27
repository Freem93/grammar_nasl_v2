#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-695. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17578);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/18 00:15:58 $");

  script_cve_id("CVE-2001-0775", "CVE-2005-0638", "CVE-2005-0639");
  script_bugtraq_id(3006);
  script_osvdb_id(13969, 14357, 14366, 14403);
  script_xref(name:"DSA", value:"695");

  script_name(english:"Debian DSA-695-1 : xli - buffer overflow, input sanitising, integer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in xli, an image viewer
for X11. The Common Vulnerabilities and Exposures project identifies
the following problems :

  - CAN-2001-0775
    A buffer overflow in the decoder for FACES format images
    could be exploited by an attacker to execute arbitrary
    code. This problem has already been fixed in xloadimage
    in DSA 069.

  - CAN-2005-0638

    Tavis Ormandy of the Gentoo Linux Security Audit Team
    has reported a flaw in the handling of compressed
    images, where shell meta-characters are not adequately
    escaped.

  - CAN-2005-0639

    Insufficient validation of image properties in have been
    discovered which could potentially result in buffer
    management errors."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=298039"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-695"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xli package.

For the stable distribution (woody) these problems have been fixed in
version 1.17.0-11woody1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xli");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2001/07/10");
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
if (deb_check(release:"3.0", prefix:"xli", reference:"1.17.0-11woody1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
