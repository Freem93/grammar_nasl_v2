#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3262. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83532);
  script_version("$Revision: 2.13 $");
  script_cvs_date("$Date: 2016/05/06 04:41:27 $");

  script_cve_id("CVE-2015-3456");
  script_bugtraq_id(74640);
  script_osvdb_id(122072);
  script_xref(name:"DSA", value:"3262");
  script_xref(name:"IAVA", value:"2015-A-0115");

  script_name(english:"Debian DSA-3262-1 : xen - security update (Venom)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jason Geffner discovered a buffer overflow in the emulated floppy disk
drive, resulting in the potential execution of arbitrary code. This
only affects HVM guests."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/xen"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3262"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xen packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 4.1.4-3+deb7u6.

The stable distribution (jessie) is already fixed through the qemu
update provided as DSA-3259-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/18");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/19");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
if (deb_check(release:"7.0", prefix:"libxen-4.1", reference:"4.1.4-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-dev", reference:"4.1.4-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-ocaml", reference:"4.1.4-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-ocaml-dev", reference:"4.1.4-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libxenstore3.0", reference:"4.1.4-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"xen-docs-4.1", reference:"4.1.4-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"xen-hypervisor-4.1-amd64", reference:"4.1.4-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"xen-hypervisor-4.1-i386", reference:"4.1.4-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"xen-system-amd64", reference:"4.1.4-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"xen-system-i386", reference:"4.1.4-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"xen-utils-4.1", reference:"4.1.4-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"xen-utils-common", reference:"4.1.4-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"xenstore-utils", reference:"4.1.4-3+deb7u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
