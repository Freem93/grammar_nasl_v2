#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2544. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62015);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/02/16 15:37:38 $");

  script_cve_id("CVE-2012-3494", "CVE-2012-3496");
  script_bugtraq_id(55400, 55412);
  script_osvdb_id(85197, 85200);
  script_xref(name:"DSA", value:"2544");

  script_name(english:"Debian DSA-2544-1 : xen - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple denial of service vulnerabilities have been discovered in
Xen, an hypervisor. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2012-3494 :
    It was discovered that set_debugreg allows writes to
    reserved bits of the DR7 debug control register on amd64
    (x86-64) paravirtualised guests, allowing a guest to
    crash the host.

  - CVE-2012-3496 :
    Matthew Daley discovered that XENMEM_populate_physmap,
    when called with the MEMF_populate_on_demand flag set, a
    BUG (detection routine) can be triggered if a
    translating paging mode is not being used, allowing a
    guest to crash the host."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/xen"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2544"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xen packages.

For the stable distribution (squeeze), these problems have been fixed
in version 4.0.1-5.4."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libxen-dev", reference:"4.0.1-5.4")) flag++;
if (deb_check(release:"6.0", prefix:"libxenstore3.0", reference:"4.0.1-5.4")) flag++;
if (deb_check(release:"6.0", prefix:"xen-docs-4.0", reference:"4.0.1-5.4")) flag++;
if (deb_check(release:"6.0", prefix:"xen-hypervisor-4.0-amd64", reference:"4.0.1-5.4")) flag++;
if (deb_check(release:"6.0", prefix:"xen-hypervisor-4.0-i386", reference:"4.0.1-5.4")) flag++;
if (deb_check(release:"6.0", prefix:"xen-utils-4.0", reference:"4.0.1-5.4")) flag++;
if (deb_check(release:"6.0", prefix:"xenstore-utils", reference:"4.0.1-5.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
