#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2501. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59779);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/02/16 15:37:38 $");

  script_cve_id("CVE-2012-0217", "CVE-2012-0218", "CVE-2012-2934");
  script_bugtraq_id(53856, 53955, 53961);
  script_osvdb_id(82933, 82934, 82943);
  script_xref(name:"DSA", value:"2501");

  script_name(english:"Debian DSA-2501-1 : xen - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Xen, a hypervisor.

  - CVE-2012-0217
    Xen does not properly handle uncanonical return
    addresses on Intel amd64 CPUs, allowing amd64 PV guests
    to elevate to hypervisor privileges. AMD processors, HVM
    and i386 guests are not affected.

  - CVE-2012-0218
    Xen does not properly handle SYSCALL and SYSENTER
    instructions in PV guests, allowing unprivileged users
    inside a guest system to crash the guest system.

  - CVE-2012-2934
    Xen does not detect old AMD CPUs affected by AMD Erratum
    #121.

For CVE-2012-2934, Xen refuses to start domUs on affected systems
unless the 'allow_unsafe' option is passed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0217"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-2934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-2934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/xen"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2501"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xen packages.

For the stable distribution (squeeze), these problems have been fixed
in version 4.0.1-5.2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/29");
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
if (deb_check(release:"6.0", prefix:"libxen-dev", reference:"4.0.1-5.2")) flag++;
if (deb_check(release:"6.0", prefix:"libxenstore3.0", reference:"4.0.1-5.2")) flag++;
if (deb_check(release:"6.0", prefix:"xen-docs-4.0", reference:"4.0.1-5.2")) flag++;
if (deb_check(release:"6.0", prefix:"xen-hypervisor-4.0-amd64", reference:"4.0.1-5.2")) flag++;
if (deb_check(release:"6.0", prefix:"xen-hypervisor-4.0-i386", reference:"4.0.1-5.2")) flag++;
if (deb_check(release:"6.0", prefix:"xen-utils-4.0", reference:"4.0.1-5.2")) flag++;
if (deb_check(release:"6.0", prefix:"xenstore-utils", reference:"4.0.1-5.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
