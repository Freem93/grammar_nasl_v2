#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-741. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18645);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/07/20 14:56:55 $");

  script_cve_id("CVE-2005-1260");
  script_osvdb_id(16767);
  script_xref(name:"DSA", value:"741");

  script_name(english:"Debian DSA-741-1 : bzip2 - infinite loop");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chris Evans discovered that a specially crafted archive can trigger an
infinite loop in bzip2, a high-quality block-sorting file compressor.
During uncompression this results in an indefinitely growing output
file which will finally fill up the disk. On systems that
automatically decompress bzip2 archives this can cause a denial of
service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=310803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-741"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bzip2 package.

For the oldstable distribution (woody) this problem has been fixed in
version 1.0.2-1.woody5.

For the stable distribution (sarge) this problem has been fixed in
version 1.0.2-7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bzip2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/08");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"bzip2", reference:"1.0.2-1.woody5")) flag++;
if (deb_check(release:"3.0", prefix:"libbz2-1.0", reference:"1.0.2-1.woody5")) flag++;
if (deb_check(release:"3.0", prefix:"libbz2-dev", reference:"1.0.2-1.woody5")) flag++;
if (deb_check(release:"3.1", prefix:"bzip2", reference:"1.0.2-7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
