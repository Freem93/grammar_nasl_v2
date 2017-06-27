#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2329. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56662);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:31:56 $");

  script_cve_id("CVE-2011-2193");
  script_bugtraq_id(48374);
  script_osvdb_id(73234, 73235);
  script_xref(name:"DSA", value:"2329");

  script_name(english:"Debian DSA-2329-1 : torque - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Bartlomiej Balcerek discovered several buffer overflows in TORQUE
server, a PBS-derived batch processing server. This allows an attacker
to crash the service or execute arbitrary code with privileges of the
server via crafted job or host names.

The oldstable distribution (lenny) does not contain torque."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/torque"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2329"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the torque packages.

For the stable distribution (squeeze), this problem has been fixed in
version 2.4.8+dfsg-9squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:torque");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libtorque2", reference:"2.4.8+dfsg-9squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libtorque2-dev", reference:"2.4.8+dfsg-9squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"torque-client", reference:"2.4.8+dfsg-9squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"torque-client-x11", reference:"2.4.8+dfsg-9squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"torque-common", reference:"2.4.8+dfsg-9squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"torque-mom", reference:"2.4.8+dfsg-9squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"torque-pam", reference:"2.4.8+dfsg-9squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"torque-scheduler", reference:"2.4.8+dfsg-9squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"torque-server", reference:"2.4.8+dfsg-9squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
