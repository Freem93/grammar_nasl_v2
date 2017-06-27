#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3272. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83789);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2015/08/14 13:54:36 $");

  script_cve_id("CVE-2015-4047");
  script_osvdb_id(122337);
  script_xref(name:"DSA", value:"3272");

  script_name(english:"Debian DSA-3272-1 : ipsec-tools - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Javantea discovered a NULL pointer dereference flaw in racoon, the
Internet Key Exchange daemon of ipsec-tools. A remote attacker can use
this flaw to cause the IKE daemon to crash via specially crafted UDP
packets, resulting in a denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=785778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/ipsec-tools"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/ipsec-tools"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3272"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ipsec-tools packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 1:0.8.0-14+deb7u1.

For the stable distribution (jessie), this problem has been fixed in
version 1:0.8.2+20140711-2+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ipsec-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/26");
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
if (deb_check(release:"7.0", prefix:"ipsec-tools", reference:"1:0.8.0-14+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"racoon", reference:"1:0.8.0-14+deb7u1")) flag++;
if (deb_check(release:"8.0", prefix:"ipsec-tools", reference:"1:0.8.2+20140711-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"racoon", reference:"1:0.8.2+20140711-2+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
