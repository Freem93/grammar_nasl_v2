#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-659. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16252);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/18 00:15:57 $");

  script_cve_id("CVE-2004-1340", "CVE-2005-0108");
  script_osvdb_id(12849, 13203);
  script_xref(name:"DSA", value:"659");

  script_name(english:"Debian DSA-659-1 : libpam-radius-auth - information leak, integer underflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two problems have been discovered in the libpam-radius-auth package,
the PAM RADIUS authentication module. The Common Vulnerabilities and
Exposures Project identifies the following problems :

  - CAN-2004-1340
    The Debian package accidentally installed its
    configuration file /etc/pam_radius_auth.conf
    world-readable. Since it may possibly contain secrets
    all local users are able to read them if the
    administrator hasn't adjusted file permissions. This
    problem is Debian specific.

  - CAN-2005-0108

    Leon Juranic discovered an integer underflow in the
    mod_auth_radius module for Apache which is also present
    in libpam-radius-auth."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-659"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libpam-radius-auth package.

For the stable distribution (woody) these problems have been fixed in
version 1.3.14-1.3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-radius-auth");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/26");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/11");
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
if (deb_check(release:"3.0", prefix:"libpam-radius-auth", reference:"1.3.14-1.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
