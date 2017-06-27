#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-536. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15373);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2013/11/14 18:38:12 $");

  script_cve_id("CVE-2004-0597", "CVE-2004-0598", "CVE-2004-0599", "CVE-2004-0768");
  script_osvdb_id(10711);
  script_xref(name:"CERT", value:"160448");
  script_xref(name:"CERT", value:"236656");
  script_xref(name:"CERT", value:"286464");
  script_xref(name:"CERT", value:"388984");
  script_xref(name:"CERT", value:"477512");
  script_xref(name:"CERT", value:"817368");
  script_xref(name:"DSA", value:"536");

  script_name(english:"Debian DSA-536-1 : libpng - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chris Evans discovered several vulnerabilities in libpng :

  - CAN-2004-0597
    Multiple buffer overflows exist, including when handling
    transparency chunk data, which could be exploited to
    cause arbitrary code to be executed when a specially
    crafted PNG image is processed

  - CAN-2004-0598

    Multiple NULL pointer dereferences in png_handle_iCPP()
    and elsewhere could be exploited to cause an application
    to crash when a specially crafted PNG image is processed

  - CAN-2004-0599

    Multiple integer overflows in the png_handle_sPLT(),
    png_read_png() functions and elsewhere could be
    exploited to cause an application to crash, or
    potentially arbitrary code to be executed, when a
    specially crafted PNG image is processed

  In addition, a bug related to CAN-2002-1363 was fixed :

  - CAN-2004-0768

    A buffer overflow could be caused by incorrect
    calculation of buffer offsets, possibly leading to the
    execution of arbitrary code"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-536"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the current stable distribution (woody), these problems have been
fixed in libpng3 version 1.2.1-1.1.woody.7 and libpng version
1.0.12-3.woody.7.

We recommend that you update your libpng and libpng3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpng");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/04");
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
if (deb_check(release:"3.0", prefix:"libpng-dev", reference:"1.2.1-1.1.woody.7")) flag++;
if (deb_check(release:"3.0", prefix:"libpng2", reference:"1.0.12-3.woody.7")) flag++;
if (deb_check(release:"3.0", prefix:"libpng2-dev", reference:"1.0.12-3.woody.7")) flag++;
if (deb_check(release:"3.0", prefix:"libpng3", reference:"1.2.1-1.1.woody.7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
