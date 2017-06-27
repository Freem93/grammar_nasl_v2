#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3006. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(77240);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/16 15:48:47 $");

  script_cve_id("CVE-2013-1432", "CVE-2013-1442", "CVE-2013-2076", "CVE-2013-2077", "CVE-2013-2078", "CVE-2013-2194", "CVE-2013-2195", "CVE-2013-2196", "CVE-2013-2211", "CVE-2013-4329", "CVE-2013-4355", "CVE-2013-4361", "CVE-2013-4368", "CVE-2013-4494", "CVE-2013-4553", "CVE-2014-1950", "CVE-2014-2599", "CVE-2014-3124", "CVE-2014-4021");
  script_bugtraq_id(60277, 60278, 60282, 60701, 60702, 60703, 60721, 60799, 62307, 62630, 62708, 62710, 62935, 63494, 63933, 65529, 66407, 67113, 68070);
  script_xref(name:"DSA", value:"3006");

  script_name(english:"Debian DSA-3006-1 : xen - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues have been discovered in the Xen
virtualisation solution which may result in information leaks or
denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/xen"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-3006"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xen packages.

For the stable distribution (wheezy), these problems have been fixed
in version 4.1.4-3+deb7u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libxen-4.1", reference:"4.1.4-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-dev", reference:"4.1.4-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-ocaml", reference:"4.1.4-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-ocaml-dev", reference:"4.1.4-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libxenstore3.0", reference:"4.1.4-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"xen-docs-4.1", reference:"4.1.4-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"xen-hypervisor-4.1-amd64", reference:"4.1.4-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"xen-hypervisor-4.1-i386", reference:"4.1.4-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"xen-system-amd64", reference:"4.1.4-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"xen-system-i386", reference:"4.1.4-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"xen-utils-4.1", reference:"4.1.4-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"xen-utils-common", reference:"4.1.4-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"xenstore-utils", reference:"4.1.4-3+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
