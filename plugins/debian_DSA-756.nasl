#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-756. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19196);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/18 00:15:58 $");

  script_cve_id("CVE-2005-1769", "CVE-2005-2095");
  script_osvdb_id(17360, 17361, 17873, 17874);
  script_xref(name:"DSA", value:"756");

  script_name(english:"Debian DSA-756-1 : squirrelmail - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Squirrelmail, a
commonly used webmail system. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CAN-2005-1769
    Martijn Brinkers discovered cross-site scripting
    vulnerabilities that allow remote attackers to inject
    arbitrary web script or HTML in the URL and e-mail
    messages.

  - CAN-2005-2095

    James Bercegay of GulfTech Security discovered a
    vulnerability in the variable handling which could lead
    to attackers altering other people's preferences and
    possibly reading them, writing files at any location
    writable for www-data and cross site scripting."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=314374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=317094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-756"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the squirrelmail package.

For the old stable distribution (woody) these problems have been fixed
in version 1.2.6-4.

For the stable distribution (sarge) these problems have been fixed in
version 1.4.4-6sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squirrelmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/15");
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
if (deb_check(release:"3.0", prefix:"squirrelmail", reference:"1.2.6-4")) flag++;
if (deb_check(release:"3.1", prefix:"squirrelmail", reference:"1.4.4-6sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
