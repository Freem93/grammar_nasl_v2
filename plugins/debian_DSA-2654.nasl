#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2654. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65793);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/25 16:11:44 $");

  script_cve_id("CVE-2012-6139");
  script_bugtraq_id(58685);
  script_osvdb_id(91609, 91610);
  script_xref(name:"DSA", value:"2654");

  script_name(english:"Debian DSA-2654-1 : libxslt - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Nicolas Gregoire discovered that libxslt, an XSLT processing runtime
library, is prone to denial of service vulnerabilities via crafted XSL
stylesheets."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=703933"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/libxslt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2654"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libxslt packages.

For the stable distribution (squeeze), this problem has been fixed in
version 1.1.26-6+squeeze3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxslt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libxslt1-dbg", reference:"1.1.26-6+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libxslt1-dev", reference:"1.1.26-6+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libxslt1.1", reference:"1.1.26-6+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"python-libxslt1", reference:"1.1.26-6+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"python-libxslt1-dbg", reference:"1.1.26-6+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"xsltproc", reference:"1.1.26-6+squeeze3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
