#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-752. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18673);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/26 16:04:30 $");

  script_cve_id("CVE-2005-0988", "CVE-2005-1228");
  script_osvdb_id(15487, 15721);
  script_xref(name:"DSA", value:"752");

  script_name(english:"Debian DSA-752-1 : gzip - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two problems have been discovered in gzip, the GNU compression
utility. The Common Vulnerabilities and Exposures project identifies
the following problems.

  - CAN-2005-0988
    Imran Ghory discovered a race condition in the
    permissions setting code in gzip. When decompressing a
    file in a directory an attacker has access to, gunzip
    could be tricked to set the file permissions to a
    different file the user has permissions to.

  - CAN-2005-1228

    Ulf Harnhammar discovered a path traversal
    vulnerability in gunzip. When gunzip is used with the -N
    option an attacker could use this vulnerability to
    create files in an arbitrary directory with the
    permissions of the user."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=305255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-752"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gzip package.

For the oldstable distribution (woody) these problems have been fixed
in version 1.3.2-3woody5.

For the stable distribution (sarge) these problems have been fixed in
version 1.3.5-10."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gzip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/04");
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
if (deb_check(release:"3.0", prefix:"gzip", reference:"1.3.2-3woody5")) flag++;
if (deb_check(release:"3.1", prefix:"gzip", reference:"1.3.5-10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
