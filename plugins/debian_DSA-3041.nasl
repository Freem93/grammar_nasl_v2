#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3041. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78027);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/05 16:01:11 $");

  script_cve_id("CVE-2013-2072", "CVE-2014-7154", "CVE-2014-7155", "CVE-2014-7156", "CVE-2014-7188");
  script_bugtraq_id(59982, 70055, 70057, 70062, 70198);
  script_osvdb_id(112435);
  script_xref(name:"DSA", value:"3041");

  script_name(english:"Debian DSA-3041-1 : xen - security update");
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
information disclosure or privilege escalation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/xen"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-3041"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xen packages.

For the stable distribution (wheezy), these problems have been fixed
in version 4.1.4-3+deb7u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libxen-4.1", reference:"4.1.4-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-dev", reference:"4.1.4-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-ocaml", reference:"4.1.4-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-ocaml-dev", reference:"4.1.4-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libxenstore3.0", reference:"4.1.4-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"xen-docs-4.1", reference:"4.1.4-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"xen-hypervisor-4.1-amd64", reference:"4.1.4-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"xen-hypervisor-4.1-i386", reference:"4.1.4-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"xen-system-amd64", reference:"4.1.4-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"xen-system-i386", reference:"4.1.4-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"xen-utils-4.1", reference:"4.1.4-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"xen-utils-common", reference:"4.1.4-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"xenstore-utils", reference:"4.1.4-3+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
