#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-667. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16341);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/18 00:15:57 $");

  script_cve_id("CVE-2005-0173", "CVE-2005-0174", "CVE-2005-0175", "CVE-2005-0194", "CVE-2005-0211");
  script_osvdb_id(12633, 13054, 13319, 13346, 13732);
  script_xref(name:"CERT", value:"625878");
  script_xref(name:"CERT", value:"886006");
  script_xref(name:"CERT", value:"924198");
  script_xref(name:"DSA", value:"667");

  script_name(english:"Debian DSA-667-1 : squid - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Squid, the internet
object cache, the popular WWW proxy cache. The Common Vulnerabilities
and Exposures project identifies the following vulnerabilities :

  - CAN-2005-0173
    LDAP is very forgiving about spaces in search filters
    and this could be abused to log in using several
    variants of the login name, possibly bypassing explicit
    access controls or confusing accounting.

  - CAN-2005-0175

    Cache pollution/poisoning via HTTP response splitting
    has been discovered.

  - CAN-2005-0194

    The meaning of the access controls becomes somewhat
    confusing if any of the referenced ACLs (access control
    lists) is declared empty, without any members.

  - CAN-2005-0211

    The length argument of the WCCP recvfrom() call is
    larger than it should be. An attacker may send a larger
    than normal WCCP packet that could overflow a buffer."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-667"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the squid package.

For the stable distribution (woody) these problems have been fixed in
version 2.4.6-2woody6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/22");
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
if (deb_check(release:"3.0", prefix:"squid", reference:"2.4.6-2woody6")) flag++;
if (deb_check(release:"3.0", prefix:"squid-cgi", reference:"2.4.6-2woody6")) flag++;
if (deb_check(release:"3.0", prefix:"squidclient", reference:"2.4.6-2woody6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
