#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2666. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66383);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/02/16 15:37:40 $");

  script_cve_id("CVE-2013-1918", "CVE-2013-1952", "CVE-2013-1964");
  script_bugtraq_id(59293, 59615, 59617);
  script_osvdb_id(92565, 92983, 92984);
  script_xref(name:"DSA", value:"2666");

  script_name(english:"Debian DSA-2666-1 : xen - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in the Xen hypervisor.
The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2013-1918
    ( XSA 45) several long latency operations are not
    preemptible.

  Some page table manipulation operations for PV guests were not made
  preemptible, allowing a malicious or buggy PV guest kernel to mount
  a denial of service attack affecting the whole system.

  - CVE-2013-1952
    ( XSA 49) VT-d interrupt remapping source validation
    flaw for bridges.

  Due to missing source validation on interrupt remapping table
  entries for MSI interrupts set up by bridge devices, a malicious
  domain with access to such a device can mount a denial of service
  attack affecting the whole system.

  - CVE-2013-1964
    ( XSA 50) grant table hypercall acquire/release
    imbalance.

  When releasing a particular, non-transitive grant after doing a
  grant copy operation, Xen incorrectly releases an unrelated grant
  reference, leading possibly to a crash of the host system.
  Furthermore information leakage or privilege escalation cannot be
  ruled out."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1918"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.xen.org/archives/html/xen-announce/2013-05/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1952"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.xen.org/archives/html/xen-announce/2013-05/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1964"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.xen.org/archives/html/xen-announce/2013-04/msg00006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1964"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.xen.org/archives/html/xen-announce/2013-04/msg00006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/xen"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/xen"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2666"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xen packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 4.0.1-5.11.

For the stable distribution (wheezy), these problems have been fixed
in version 4.1.4-3+deb7u1.

Note that for the stable (wheezy), testing and unstable distribution,
CVE-2013-1964 ( XSA 50) was already fixed in version 4.1.4-3."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libxen-dev", reference:"4.0.1-5.11")) flag++;
if (deb_check(release:"6.0", prefix:"libxenstore3.0", reference:"4.0.1-5.11")) flag++;
if (deb_check(release:"6.0", prefix:"xen-docs-4.0", reference:"4.0.1-5.11")) flag++;
if (deb_check(release:"6.0", prefix:"xen-hypervisor-4.0-amd64", reference:"4.0.1-5.11")) flag++;
if (deb_check(release:"6.0", prefix:"xen-hypervisor-4.0-i386", reference:"4.0.1-5.11")) flag++;
if (deb_check(release:"6.0", prefix:"xen-utils-4.0", reference:"4.0.1-5.11")) flag++;
if (deb_check(release:"6.0", prefix:"xenstore-utils", reference:"4.0.1-5.11")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-4.1", reference:"4.1.4-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-dev", reference:"4.1.4-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-ocaml", reference:"4.1.4-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-ocaml-dev", reference:"4.1.4-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxenstore3.0", reference:"4.1.4-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"xen-docs-4.1", reference:"4.1.4-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"xen-hypervisor-4.1-amd64", reference:"4.1.4-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"xen-hypervisor-4.1-i386", reference:"4.1.4-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"xen-system-amd64", reference:"4.1.4-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"xen-system-i386", reference:"4.1.4-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"xen-utils-4.1", reference:"4.1.4-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"xen-utils-common", reference:"4.1.4-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"xenstore-utils", reference:"4.1.4-3+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
