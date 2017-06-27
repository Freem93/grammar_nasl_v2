#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-705. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18010);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/18 00:15:58 $");

  script_cve_id("CVE-2003-0854", "CVE-2005-0256");
  script_osvdb_id(4620, 14203);
  script_xref(name:"DSA", value:"705");

  script_name(english:"Debian DSA-705-1 : wu-ftpd - missing input sanitising");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several denial of service conditions have been discovered in wu-ftpd,
the popular FTP daemon. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CAN-2005-0256
    Adam Zabrocki discovered a denial of service condition
    in wu-ftpd that could be exploited by a remote user and
    cause the server to slow down by resource exhaustion.

  - CAN-2003-0854

    Georgi Guninski discovered that /bin/ls may be called
    from within wu-ftpd in a way that will result in large
    memory consumption and hence slow down the server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-705"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wu-ftpd package.

For the stable distribution (woody) these problems have been fixed in
version 2.6.2-3woody5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wu-ftpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/11");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/05/16");
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
if (deb_check(release:"3.0", prefix:"wu-ftpd", reference:"2.6.2-3woody5")) flag++;
if (deb_check(release:"3.0", prefix:"wu-ftpd-academ", reference:"2.6.2-3woody5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
