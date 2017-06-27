#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-717. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18153);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/26 16:04:30 $");

  script_cve_id("CVE-2003-0826", "CVE-2005-0814");
  script_osvdb_id(11744, 14825);
  script_xref(name:"DSA", value:"717");

  script_name(english:"Debian DSA-717-1 : lsh-utils - buffer overflow, typo");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security relevant problems have been discovered in lsh, the
alternative secure shell v2 (SSH2) protocol server. The Common
Vulnerabilities and Exposures project identifies the following
vulnerabilities :

  - CAN-2003-0826
    Bennett Todd discovered a heap buffer overflow in lshd
    which could lead to the execution of arbitrary code.

  - CAN-2005-0814

    Niels Moller discovered a denial of service condition
    in lshd."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=211662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-717"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the lsh-server package.

For the stable distribution (woody) these problems have been fixed in
version 1.2.5-2woody3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lsh-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/28");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/09/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"lsh-client", reference:"1.2.5-2woody3")) flag++;
if (deb_check(release:"3.0", prefix:"lsh-server", reference:"1.2.5-2woody3")) flag++;
if (deb_check(release:"3.0", prefix:"lsh-utils", reference:"1.2.5-2woody3")) flag++;
if (deb_check(release:"3.0", prefix:"lsh-utils-doc", reference:"1.2.5-2woody3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
