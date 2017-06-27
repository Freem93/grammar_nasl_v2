#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1384. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26931);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-1320", "CVE-2007-4993");
  script_osvdb_id(41340);
  script_xref(name:"DSA", value:"1384");

  script_name(english:"Debian DSA-1384-1 : xen-utils - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several local vulnerabilities have been discovered in the Xen
hypervisor packages which may lead to the execution of arbitrary code.
The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2007-4993
    By use of a specially crafted grub configuration file a
    domU user may be able to execute arbitrary code upon the
    dom0 when pygrub is being used.

  - CVE-2007-1320
    Multiple heap-based buffer overflows in the Cirrus VGA
    extension, provided by QEMU, may allow local users to
    execute arbitrary code via 'bitblt' heap overflow."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=444430"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=444007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1384"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xen-utils package.

For the stable distribution (etch), these problems have been fixed in
version 3.0.3-0-3."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/09");
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
if (deb_check(release:"4.0", prefix:"xen-docs-3.0", reference:"3.0.3-0-3")) flag++;
if (deb_check(release:"4.0", prefix:"xen-hypervisor-3.0.3-1-amd64", reference:"3.0.3-0-3")) flag++;
if (deb_check(release:"4.0", prefix:"xen-hypervisor-3.0.3-1-i386", reference:"3.0.3-0-3")) flag++;
if (deb_check(release:"4.0", prefix:"xen-hypervisor-3.0.3-1-i386-pae", reference:"3.0.3-0-3")) flag++;
if (deb_check(release:"4.0", prefix:"xen-ioemu-3.0.3-1", reference:"3.0.3-0-3")) flag++;
if (deb_check(release:"4.0", prefix:"xen-utils-3.0.3-1", reference:"3.0.3-0-3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
