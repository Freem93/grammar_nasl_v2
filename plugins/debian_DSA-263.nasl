#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-263. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15100);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2013/05/18 00:07:14 $");

  script_cve_id("CVE-2003-0146");
  script_osvdb_id(4810);
  script_xref(name:"CERT", value:"378049");
  script_xref(name:"CERT", value:"630433");
  script_xref(name:"DSA", value:"263");

  script_name(english:"Debian DSA-263-1 : netpbm-free - math overflow errors");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Al Viro and Alan Cox discovered several maths overflow errors in
NetPBM, a set of graphics conversion tools. These programs are not
installed setuid root but are often installed to prepare data for
processing. These vulnerabilities may allow remote attackers to cause
a denial of service or execute arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-263"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the netpbm package.

For the stable distribution (woody) this problem has been fixed in
version 9.20-8.2.

The old stable distribution (potato) does not seem to be affected by
this problem."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:netpbm-free");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/05/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"libnetpbm9", reference:"9.20-8.2")) flag++;
if (deb_check(release:"3.0", prefix:"libnetpbm9-dev", reference:"9.20-8.2")) flag++;
if (deb_check(release:"3.0", prefix:"netpbm", reference:"9.20-8.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
