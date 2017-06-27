#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-498. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15335);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/05 16:01:12 $");

  script_cve_id("CVE-2004-0421");
  script_bugtraq_id(10244);
  script_osvdb_id(5726, 73493);
  script_xref(name:"DSA", value:"498");

  script_name(english:"Debian DSA-498-1 : libpng - out of bound access");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Steve Grubb discovered a problem in the Portable Network Graphics
library libpng which is utilised in several applications. When
processing a broken PNG image, the error handling routine will access
memory that is out of bounds when creating an error message. Depending
on machine architecture, bounds checking and other protective
measures, this problem could cause the program to crash if a defective
or intentionally prepared PNG image file is handled by libpng.

This could be used as a denial of service attack against various
programs that link against this library. The following commands will
show you which packages utilise this library and whose programs should
probably restarted after an upgrade :

    apt-cache showpkg libpng2 apt-cache showpkg libpng3

The following security matrix explains which package versions will
contain a correction.

  Package            stable (woody)     unstable (sid)     
  libpng             1.0.12-3.woody.5   1.0.15-5           
  libpng3            1.2.1-1.1.woody.5  1.2.5.0-6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-498"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the libpng and related packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpng3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"libpng-dev", reference:"1.2.1-1.1.woody.5")) flag++;
if (deb_check(release:"3.0", prefix:"libpng2", reference:"1.0.12-3.woody.5")) flag++;
if (deb_check(release:"3.0", prefix:"libpng2-dev", reference:"1.0.12-3.woody.5")) flag++;
if (deb_check(release:"3.0", prefix:"libpng3", reference:"1.2.1-1.1.woody.5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
