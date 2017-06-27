#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-897. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22763);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/06 20:34:49 $");

  script_cve_id("CVE-2005-0870", "CVE-2005-3347", "CVE-2005-3348");
  script_xref(name:"DSA", value:"897");

  script_name(english:"Debian DSA-897-1 : phpsysinfo - programming errors");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in phpsysinfo, a PHP
based host information application. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2005-0870
    Maksymilian Arciemowicz discovered several cross site
    scripting problems, of which not all were fixed in DSA
    724.

  - CVE-2005-3347
    Christopher Kunz discovered that local variables get
    overwritten unconditionally and are trusted later, which
    could lead to the inclusion of arbitrary files.

  - CVE-2005-3348
    Christopher Kunz discovered that user-supplied input is
    used unsanitised, causing a HTTP Response splitting
    problem."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=301118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-897"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the phpsysinfo package.

For the old stable distribution (woody) these problems have been fixed
in version 2.0-3woody3.

For the stable distribution (sarge) these problems have been fixed in
version 2.3-4sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(22, 352);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:phpsysinfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"phpsysinfo", reference:"2.0-3woody3")) flag++;
if (deb_check(release:"3.1", prefix:"phpsysinfo", reference:"2.3-4sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
