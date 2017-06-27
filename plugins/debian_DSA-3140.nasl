#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3140. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81027);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/05 16:01:11 $");

  script_cve_id("CVE-2014-8594", "CVE-2014-8595", "CVE-2014-8866", "CVE-2014-8867", "CVE-2014-9030");
  script_bugtraq_id(71149, 71151, 71207, 71331, 71332);
  script_osvdb_id(114852, 115137, 115138);
  script_xref(name:"DSA", value:"3140");

  script_name(english:"Debian DSA-3140-1 : xen - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues have been discovered in the Xen
virtualisation solution which may result in denial of service,
information disclosure or privilege escalation.

  - CVE-2014-8594
    Roger Pau Monne and Jan Beulich discovered that
    incomplete restrictions on MMU update hypercalls may
    result in privilege escalation.

  - CVE-2014-8595
    Jan Beulich discovered that missing privilege level
    checks in the x86 emulation of far branches may result
    in privilege escalation.

  - CVE-2014-8866
    Jan Beulich discovered that an error in compatibility
    mode hypercall argument translation may result in denial
    of service.

  - CVE-2014-8867
    Jan Beulich discovered that an insufficient restriction
    in acceleration support for the 'REP MOVS' instruction
    may result in denial of service.

  - CVE-2014-9030
    Andrew Cooper discovered a page reference leak in
    MMU_MACHPHYS_UPDATE handling, resulting in denial of
    service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-8594"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-8595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-8866"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-8867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9030"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/xen"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3140"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xen packages.

For the stable distribution (wheezy), these problems have been fixed
in version 4.1.4-3+deb7u4.

For the upcoming stable distribution (jessie), these problems have
been fixed in version 4.4.1-4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libxen-4.1", reference:"4.1.4-3+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-dev", reference:"4.1.4-3+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-ocaml", reference:"4.1.4-3+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-ocaml-dev", reference:"4.1.4-3+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libxenstore3.0", reference:"4.1.4-3+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"xen-docs-4.1", reference:"4.1.4-3+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"xen-hypervisor-4.1-amd64", reference:"4.1.4-3+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"xen-hypervisor-4.1-i386", reference:"4.1.4-3+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"xen-system-amd64", reference:"4.1.4-3+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"xen-system-i386", reference:"4.1.4-3+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"xen-utils-4.1", reference:"4.1.4-3+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"xen-utils-common", reference:"4.1.4-3+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"xenstore-utils", reference:"4.1.4-3+deb7u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
