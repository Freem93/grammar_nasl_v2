#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3533. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90252);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/06 20:25:08 $");

  script_cve_id("CVE-2016-2074");
  script_osvdb_id(136404);
  script_xref(name:"DSA", value:"3533");

  script_name(english:"Debian DSA-3533-1 : openvswitch - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Kashyap Thimmaraju and Bhargava Shastry discovered a remotely
triggerable buffer overflow vulnerability in openvswitch, a production
quality, multilayer virtual switch implementation. Specially crafted
MPLS packets could overflow the buffer reserved for MPLS labels in an
OVS internal data structure. A remote attacker can take advantage of
this flaw to cause a denial of service, or potentially, execution of
arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/openvswitch"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3533"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openvswitch packages.

For the stable distribution (jessie), this problem has been fixed in
version 2.3.0+git20140819-3+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"openvswitch-common", reference:"2.3.0+git20140819-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"openvswitch-dbg", reference:"2.3.0+git20140819-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"openvswitch-ipsec", reference:"2.3.0+git20140819-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"openvswitch-pki", reference:"2.3.0+git20140819-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"openvswitch-switch", reference:"2.3.0+git20140819-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"openvswitch-test", reference:"2.3.0+git20140819-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"openvswitch-vtep", reference:"2.3.0+git20140819-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"python-openvswitch", reference:"2.3.0+git20140819-3+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
