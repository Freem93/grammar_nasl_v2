#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3143. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81056);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/07/23 15:02:09 $");

  script_cve_id("CVE-2015-0377", "CVE-2015-0418");
  script_bugtraq_id(72194, 72219);
  script_osvdb_id(117338, 117344);
  script_xref(name:"DSA", value:"3143");

  script_name(english:"Debian DSA-3143-1 : virtualbox - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities have been discovered in VirtualBox, a x86
virtualisation solution, which might result in denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/virtualbox"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3143"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the virtualbox packages.

For the stable distribution (wheezy), these problems have been fixed
in version 4.1.18-dfsg-2+deb7u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:virtualbox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"virtualbox", reference:"4.1.18-dfsg-2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-dbg", reference:"4.1.18-dfsg-2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-dkms", reference:"4.1.18-dfsg-2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-fuse", reference:"4.1.18-dfsg-2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-guest-dkms", reference:"4.1.18-dfsg-2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-guest-source", reference:"4.1.18-dfsg-2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-guest-utils", reference:"4.1.18-dfsg-2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-guest-x11", reference:"4.1.18-dfsg-2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-ose", reference:"4.1.18-dfsg-2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-ose-dbg", reference:"4.1.18-dfsg-2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-ose-dkms", reference:"4.1.18-dfsg-2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-ose-fuse", reference:"4.1.18-dfsg-2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-ose-guest-dkms", reference:"4.1.18-dfsg-2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-ose-guest-source", reference:"4.1.18-dfsg-2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-ose-guest-utils", reference:"4.1.18-dfsg-2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-ose-guest-x11", reference:"4.1.18-dfsg-2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-ose-qt", reference:"4.1.18-dfsg-2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-ose-source", reference:"4.1.18-dfsg-2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-qt", reference:"4.1.18-dfsg-2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-source", reference:"4.1.18-dfsg-2+deb7u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
