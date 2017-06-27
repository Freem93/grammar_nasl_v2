#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-843. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19847);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/18 00:15:59 $");

  script_cve_id("CVE-2005-2945", "CVE-2005-2992");
  script_osvdb_id(19458, 19984);
  script_xref(name:"DSA", value:"843");

  script_name(english:"Debian DSA-843-1 : arc - insecure temporary file");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities have been discovered in the ARC archive program
under Unix. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CAN-2005-2945
    Eric Romang discovered that the ARC archive program
    under Unix creates a temporary file with insecure
    permissions which may lead to an attacker stealing
    sensitive information.

  - CAN-2005-2992

    Joey Schulze discovered that the temporary file was
    created in an insecure fashion as well, leaving it open
    to a classic symlink attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-843"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the arc package.

The old stable distribution (woody) does not contain arc packages.

For the stable distribution (sarge) these problems have been fixed in
version 5.21l-1sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:arc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/16");
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
if (deb_check(release:"3.1", prefix:"arc", reference:"5.21l-1sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
