#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3853. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100178);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/18 13:19:45 $");

  script_cve_id("CVE-2016-10188", "CVE-2016-10189");
  script_osvdb_id(151164, 151165);
  script_xref(name:"DSA", value:"3853");

  script_name(english:"Debian DSA-3853-1 : bitlbee - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that bitlbee, an IRC to other chat networks gateway,
contained issues that allowed a remote attacker to cause a denial of
service (via application crash), or potentially execute arbitrary
commands."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/bitlbee"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2017/dsa-3853"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bitlbee packages.

For the stable distribution (jessie), these problems have been fixed
in version 3.2.2-2+deb8u1.

For the upcoming stable (stretch) and unstable (sid) distributions,
these problems have been fixed in version 3.5-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bitlbee");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"bitlbee", reference:"3.2.2-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"bitlbee-common", reference:"3.2.2-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"bitlbee-dev", reference:"3.2.2-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"bitlbee-libpurple", reference:"3.2.2-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"bitlbee-plugin-otr", reference:"3.2.2-2+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
