#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-886. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22752);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/05/18 00:19:43 $");

  script_cve_id("CVE-2005-2659", "CVE-2005-2930", "CVE-2005-3318");
  script_bugtraq_id(15211);
  script_osvdb_id(20335, 20512, 20974);
  script_xref(name:"DSA", value:"886");

  script_name(english:"Debian DSA-886-1 : chmlib - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in chmlib, a library for
dealing with CHM format files. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2005-2659
    Palasik Sandor discovered a buffer overflow in the LZX
    decompression method.

  - CVE-2005-2930
    A buffer overflow has been discovered that could lead to
    the execution of arbitrary code.

  - CVE-2005-3318
    Sven Tantau discovered a buffer overflow that could lead
    to the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-886"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chmlib packages.

The old stable distribution (woody) does not contain chmlib packages.

For the stable distribution (sarge) these problems have been fixed in
version 0.35-6sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chmlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"chmlib", reference:"0.35-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"chmlib-bin", reference:"0.35-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"chmlib-dev", reference:"0.35-6sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
