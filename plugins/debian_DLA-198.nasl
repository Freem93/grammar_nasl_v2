#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-198-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83002);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/12/02 20:08:16 $");

  script_cve_id("CVE-2014-6422", "CVE-2014-6423", "CVE-2014-6428", "CVE-2014-6429", "CVE-2014-6430", "CVE-2014-6431", "CVE-2014-6432", "CVE-2014-8710", "CVE-2014-8711", "CVE-2014-8712", "CVE-2014-8713", "CVE-2014-8714", "CVE-2015-0562", "CVE-2015-0564", "CVE-2015-2188", "CVE-2015-2191");
  script_bugtraq_id(69853, 69856, 69857, 69858, 69859, 69860, 69865, 71069, 71070, 71071, 71072, 71073, 71921, 71922, 72941, 72942);
  script_osvdb_id(111598, 111600, 111605, 111633, 111634, 111635, 111636, 114572, 114573, 114574, 114579, 114580, 116811, 116813, 119256, 119259);

  script_name(english:"Debian DLA-198-1 : wireshark security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The following vulnerabilities were discovered in the Squeeze's
Wireshark version :

CVE-2015-2188 The WCP dissector could crash CVE-2015-0564 Wireshark
could crash while decypting TLS/SSL sessions CVE-2015-0562 The DEC DNA
Routing Protocol dissector could crash CVE-2014-8714 TN5250 infinite
loops CVE-2014-8713 NCP crashes CVE-2014-8712 NCP crashes
CVE-2014-8711 AMQP crash CVE-2014-8710 SigComp UDVM buffer overflow
CVE-2014-6432 Sniffer file parser crash CVE-2014-6431 Sniffer file
parser crash CVE-2014-6430 Sniffer file parser crash CVE-2014-6429
Sniffer file parser crash CVE-2014-6428 SES dissector crash
CVE-2014-6423 MEGACO dissector infinite loop CVE-2014-6422 RTP
dissector crash

Since back-porting upstream patches to 1.2.11-6+squeeze15 did not fix
all the outstanding issues and some issues are not even tracked
publicly the LTS Team decided to sync squeeze-lts's wireshark package
with wheezy-security to provide the best possible security support.

Note that upgrading Wireshark from 1.2.x to 1.8.x introduces several
backward-incompatible changes in package structure, shared library
API/ABI, availability of dissectors and in syntax of command line
parameters.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/04/msg00020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/wireshark"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/23");
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
if (deb_check(release:"6.0", prefix:"libwireshark-data", reference:"1.8.2-5wheezy15~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libwireshark-dev", reference:"1.8.2-5wheezy15~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libwireshark2", reference:"1.8.2-5wheezy15~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libwiretap-dev", reference:"1.8.2-5wheezy15~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libwiretap2", reference:"1.8.2-5wheezy15~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libwsutil-dev", reference:"1.8.2-5wheezy15~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libwsutil2", reference:"1.8.2-5wheezy15~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"tshark", reference:"1.8.2-5wheezy15~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"wireshark", reference:"1.8.2-5wheezy15~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"wireshark-common", reference:"1.8.2-5wheezy15~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"wireshark-dbg", reference:"1.8.2-5wheezy15~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"wireshark-dev", reference:"1.8.2-5wheezy15~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"wireshark-doc", reference:"1.8.2-5wheezy15~deb6u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
