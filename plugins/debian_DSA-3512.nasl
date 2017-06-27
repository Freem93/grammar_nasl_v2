#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3512. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89794);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/12/06 20:25:08 $");

  script_cve_id("CVE-2016-2851");
  script_osvdb_id(135667);
  script_xref(name:"DSA", value:"3512");

  script_name(english:"Debian DSA-3512-1 : libotr - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Markus Vervier of X41 D-Sec GmbH discovered an integer overflow
vulnerability in libotr, an off-the-record (OTR) messaging library, in
the way how the sizes of portions of incoming messages were stored. A
remote attacker can exploit this flaw by sending crafted messages to
an application that is using libotr to perform denial of service
attacks (application crash), or potentially, execute arbitrary code
with the privileges of the user running the application."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libotr"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libotr"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3512"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libotr packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 3.2.1-1+deb7u2.

For the stable distribution (jessie), this problem has been fixed in
version 4.1.0-2+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libotr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/10");
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
if (deb_check(release:"7.0", prefix:"libotr2", reference:"3.2.1-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libotr2-bin", reference:"3.2.1-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libotr2-dev", reference:"3.2.1-1+deb7u2")) flag++;
if (deb_check(release:"8.0", prefix:"libotr5", reference:"4.1.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libotr5-bin", reference:"4.1.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libotr5-dev", reference:"4.1.0-2+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
