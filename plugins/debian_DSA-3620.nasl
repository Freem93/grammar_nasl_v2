#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3620. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(92328);
  script_version("$Revision: 2.10 $");
  script_cvs_date("$Date: 2017/03/20 15:44:32 $");

  script_cve_id("CVE-2016-2365", "CVE-2016-2366", "CVE-2016-2367", "CVE-2016-2368", "CVE-2016-2369", "CVE-2016-2370", "CVE-2016-2371", "CVE-2016-2372", "CVE-2016-2373", "CVE-2016-2374", "CVE-2016-2375", "CVE-2016-2376", "CVE-2016-2377", "CVE-2016-2378", "CVE-2016-2380", "CVE-2016-4323");
  script_osvdb_id(140394, 140395, 140396, 140397, 140398, 140399, 140400, 140401, 140402, 140403, 140404, 140405, 140406, 140407, 140408, 140409);
  script_xref(name:"DSA", value:"3620");

  script_name(english:"Debian DSA-3620-1 : pidgin - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Yves Younan of Cisco Talos discovered several vulnerabilities in the
MXit protocol support in pidgin, a multi-protocol instant messaging
client. A remote attacker can take advantage of these flaws to cause a
denial of service (application crash), overwrite files, information
disclosure, or potentially to execute arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/pidgin"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3620"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the pidgin packages.

For the stable distribution (jessie), these problems have been fixed
in version 2.11.0-0+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"finch", reference:"2.11.0-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"finch-dev", reference:"2.11.0-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpurple-bin", reference:"2.11.0-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpurple-dev", reference:"2.11.0-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpurple0", reference:"2.11.0-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"pidgin", reference:"2.11.0-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"pidgin-data", reference:"2.11.0-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"pidgin-dbg", reference:"2.11.0-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"pidgin-dev", reference:"2.11.0-0+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
