#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1284. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25151);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-1320", "CVE-2007-1321", "CVE-2007-1322", "CVE-2007-1366", "CVE-2007-2893", "CVE-2007-5729", "CVE-2007-5730");
  script_osvdb_id(35496, 42985, 42986);
  script_xref(name:"DSA", value:"1284");

  script_name(english:"Debian DSA-1284-1 : qemu - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the QEMU processor
emulator, which may lead to the execution of arbitrary code or denial
of service. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2007-1320
    Tavis Ormandy discovered that a memory management
    routine of the Cirrus video driver performs insufficient
    bounds checking, which might allow the execution of
    arbitrary code through a heap overflow.

  - CVE-2007-1321
    Tavis Ormandy discovered that the NE2000 network driver
    and the socket code perform insufficient input
    validation, which might allow the execution of arbitrary
    code through a heap overflow.

  - CVE-2007-1322
    Tavis Ormandy discovered that the 'icebp' instruction
    can be abused to terminate the emulation, resulting in
    denial of service.

  - CVE-2007-1323
    Tavis Ormandy discovered that the NE2000 network driver
    and the socket code perform insufficient input
    validation, which might allow the execution of arbitrary
    code through a heap overflow.

  - CVE-2007-1366
    Tavis Ormandy discovered that the 'aam' instruction can
    be abused to crash qemu through a division by zero,
    resulting in denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1366"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1284"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the qemu packages.

For the oldstable distribution (sarge) these problems have been fixed
in version 0.6.1+20050407-1sarge1.

For the stable distribution (etch) these problems have been fixed in
version 0.8.2-4etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"qemu", reference:"0.6.1+20050407-1sarge1")) flag++;
if (deb_check(release:"4.0", prefix:"qemu", reference:"0.8.2-4etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
