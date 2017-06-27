#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-734. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18623);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/18 00:15:58 $");

  script_cve_id("CVE-2005-1269", "CVE-2005-1934");
  script_osvdb_id(17236, 17237);
  script_xref(name:"DSA", value:"734");

  script_name(english:"Debian DSA-734-1 : gaim - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two denial of service problems have been discovered in Gaim, a
multi-protocol instant messaging client. The Common Vulnerabilities
and Exposures project identifies the following problems :

  - CAN-2005-1269
    A malformed Yahoo filename can result in a crash of the
    application.

  - CAN-2005-1934

    A malformed MSN message can lead to incorrect memory
    allocation resulting in a crash of the application.

The old stable distribution (woody) does not seem to be affected."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-734"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gaim package.

For the stable distribution (sarge) these problems have been fixed in
version 1.2.1-1.3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gaim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/10");
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
if (deb_check(release:"3.1", prefix:"gaim", reference:"1.2.1-1.3")) flag++;
if (deb_check(release:"3.1", prefix:"gaim-data", reference:"1.2.1-1.3")) flag++;
if (deb_check(release:"3.1", prefix:"gaim-dev", reference:"1.2.1-1.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
