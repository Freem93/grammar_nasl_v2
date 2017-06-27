#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-497-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(91395);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/06 20:03:51 $");

  script_cve_id("CVE-2012-6052", "CVE-2012-6053", "CVE-2012-6054", "CVE-2012-6055", "CVE-2012-6056", "CVE-2012-6057", "CVE-2012-6058", "CVE-2012-6059", "CVE-2012-6060", "CVE-2012-6061", "CVE-2012-6062", "CVE-2013-1572", "CVE-2013-1573", "CVE-2013-1574", "CVE-2013-1575", "CVE-2013-1576", "CVE-2013-1577", "CVE-2013-1578", "CVE-2013-1579", "CVE-2013-1580", "CVE-2013-1581", "CVE-2013-2476", "CVE-2013-2479", "CVE-2013-2482", "CVE-2013-2485", "CVE-2013-2486", "CVE-2013-2487", "CVE-2013-4079", "CVE-2013-4080", "CVE-2013-4927", "CVE-2013-4929", "CVE-2013-4931", "CVE-2013-5719", "CVE-2013-5721", "CVE-2013-6339", "CVE-2013-7112", "CVE-2015-6243", "CVE-2015-6246", "CVE-2015-6248", "CVE-2016-4006", "CVE-2016-4079", "CVE-2016-4080", "CVE-2016-4081", "CVE-2016-4082", "CVE-2016-4085");
  script_bugtraq_id(56729, 57616, 58350, 58353, 58358, 58362, 58363, 58364, 60448, 60498, 60503, 61471, 62318, 62320, 63501, 64411);
  script_osvdb_id(97220, 97222, 126174, 126177, 126179, 136225, 136558, 137565, 137566, 137567, 137573);

  script_name(english:"Debian DLA-497-1 : wireshark security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in the dissectors/parsers for
PKTC, IAX2, GSM CBCH and NCP which could result in denial of service.

This update also fixes many older less important issues by updating
the package to the version found in Debian 8 also known as Jessie.

For Debian 7 'Wheezy', these problems have been fixed in version
1.12.1+g01b65bf-4+deb8u6~deb7u1.

We recommend that you upgrade your wireshark packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/05/msg00051.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/wireshark"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwiretap-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwiretap2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwsutil-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwsutil2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/01");
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
if (deb_check(release:"7.0", prefix:"libwireshark-data", reference:"1.12.1+g01b65bf-4+deb8u6~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libwireshark-dev", reference:"1.12.1+g01b65bf-4+deb8u6~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libwireshark2", reference:"1.12.1+g01b65bf-4+deb8u6~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libwiretap-dev", reference:"1.12.1+g01b65bf-4+deb8u6~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libwiretap2", reference:"1.12.1+g01b65bf-4+deb8u6~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libwsutil-dev", reference:"1.12.1+g01b65bf-4+deb8u6~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libwsutil2", reference:"1.12.1+g01b65bf-4+deb8u6~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"tshark", reference:"1.12.1+g01b65bf-4+deb8u6~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wireshark", reference:"1.12.1+g01b65bf-4+deb8u6~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wireshark-common", reference:"1.12.1+g01b65bf-4+deb8u6~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wireshark-dbg", reference:"1.12.1+g01b65bf-4+deb8u6~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wireshark-dev", reference:"1.12.1+g01b65bf-4+deb8u6~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wireshark-doc", reference:"1.12.1+g01b65bf-4+deb8u6~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
