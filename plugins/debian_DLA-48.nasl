#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-48-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82195);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/23 20:31:32 $");

  script_cve_id("CVE-2014-0591");
  script_bugtraq_id(64801);
  script_osvdb_id(101973);

  script_name(english:"Debian DLA-48-1 : bind9 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fix denial of service attack when processing NSEC3-signed zone
queries, fixed by not calling memcpy with overlapping ranges in
bin/named/query.c. - patch backported from 9.8.6-P2 by Marc
Deslauriers from the Ubuntu Security team for USN-2081-1.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2014/09/msg00005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/bind9"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dnsutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbind-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbind9-60");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdns69");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisc62");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisccc60");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisccfg62");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblwres60");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lwresd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
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
if (deb_check(release:"6.0", prefix:"bind9", reference:"9.7.3.dfsg-1~squeeze12")) flag++;
if (deb_check(release:"6.0", prefix:"bind9-doc", reference:"9.7.3.dfsg-1~squeeze12")) flag++;
if (deb_check(release:"6.0", prefix:"bind9-host", reference:"9.7.3.dfsg-1~squeeze12")) flag++;
if (deb_check(release:"6.0", prefix:"bind9utils", reference:"9.7.3.dfsg-1~squeeze12")) flag++;
if (deb_check(release:"6.0", prefix:"dnsutils", reference:"9.7.3.dfsg-1~squeeze12")) flag++;
if (deb_check(release:"6.0", prefix:"host", reference:"9.7.3.dfsg-1~squeeze12")) flag++;
if (deb_check(release:"6.0", prefix:"libbind-dev", reference:"9.7.3.dfsg-1~squeeze12")) flag++;
if (deb_check(release:"6.0", prefix:"libbind9-60", reference:"9.7.3.dfsg-1~squeeze12")) flag++;
if (deb_check(release:"6.0", prefix:"libdns69", reference:"9.7.3.dfsg-1~squeeze12")) flag++;
if (deb_check(release:"6.0", prefix:"libisc62", reference:"9.7.3.dfsg-1~squeeze12")) flag++;
if (deb_check(release:"6.0", prefix:"libisccc60", reference:"9.7.3.dfsg-1~squeeze12")) flag++;
if (deb_check(release:"6.0", prefix:"libisccfg62", reference:"9.7.3.dfsg-1~squeeze12")) flag++;
if (deb_check(release:"6.0", prefix:"liblwres60", reference:"9.7.3.dfsg-1~squeeze12")) flag++;
if (deb_check(release:"6.0", prefix:"lwresd", reference:"9.7.3.dfsg-1~squeeze12")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
