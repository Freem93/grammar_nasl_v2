#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-455-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90873);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/05/04 18:02:23 $");

  script_cve_id("CVE-2014-2286", "CVE-2014-4046", "CVE-2014-6610", "CVE-2014-8412", "CVE-2014-8418", "CVE-2015-3008");
  script_bugtraq_id(66093, 68040, 69962, 71218, 71227, 74022);
  script_osvdb_id(104327, 108083, 111729, 114918, 114923, 120492);

  script_name(english:"Debian DLA-455-1 : asterisk security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2014-6610 Asterisk Open Source 11.x before 11.12.1 and 12.x before
12.5.1 and Certified Asterisk 11.6 before 11.6-cert6, when using the
res_fax_spandsp module, allows remote authenticated users to cause a
denial of service (crash) via an out of call message, which is not
properly handled in the ReceiveFax dialplan application.

CVE-2014-4046 Asterisk Open Source 11.x before 11.10.1 and 12.x before
12.3.1 and Certified Asterisk 11.6 before 11.6-cert3 allows remote
authenticated Manager users to execute arbitrary shell commands via a
MixMonitor action.

CVE-2014-2286 main/http.c in Asterisk Open Source 1.8.x before
1.8.26.1, 11.8.x before 11.8.1, and 12.1.x before 12.1.1, and
Certified Asterisk 1.8.x before 1.8.15-cert5 and 11.6 before
11.6-cert2, allows remote attackers to cause a denial of service
(stack consumption) and possibly execute arbitrary code via an HTTP
request with a large number of Cookie headers.

CVE-2014-8412 The (1) VoIP channel drivers, (2) DUNDi, and (3)
Asterisk Manager Interface (AMI) in Asterisk Open Source 1.8.x before
1.8.32.1, 11.x before 11.14.1, 12.x before 12.7.1, and 13.x before
13.0.1 and Certified Asterisk 1.8.28 before 1.8.28-cert3 and 11.6
before 11.6-cert8 allows remote attackers to bypass the ACL
restrictions via a packet with a source IP that does not share the
address family as the first ACL entry.

CVE-2014-8418 The DB dialplan function in Asterisk Open Source 1.8.x
before 1.8.32, 11.x before 11.1.4.1, 12.x before 12.7.1, and 13.x
before 13.0.1 and Certified Asterisk 1.8 before 1.8.28-cert8 and 11.6
before 11.6-cert8 allows remote authenticated users to gain privileges
via a call from an external protocol, as demonstrated by the AMI
protocol.

CVE-2015-3008 Asterisk Open Source 1.8 before 1.8.32.3, 11.x before
11.17.1, 12.x before 12.8.2, and 13.x before 13.3.2 and Certified
Asterisk 1.8.28 before 1.8.28-cert5, 11.6 before 11.6-cert11, and 13.1
before 13.1-cert2, when registering a SIP TLS device, does not
properly handle a null byte in a domain name in the subject's Common
Name (CN) field of an X.509 certificate, which allows
man-in-the-middle attackers to spoof arbitrary SSL servers via a
crafted certificate issued by a legitimate Certification Authority.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/05/msg00005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/asterisk"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-dahdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-mobile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-mp3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-ooh323");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-voicemail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-voicemail-imapstorage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-voicemail-odbcstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/04");
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
if (deb_check(release:"7.0", prefix:"asterisk", reference:"1:1.8.13.1~dfsg1-3+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-config", reference:"1:1.8.13.1~dfsg1-3+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-dahdi", reference:"1:1.8.13.1~dfsg1-3+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-dbg", reference:"1:1.8.13.1~dfsg1-3+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-dev", reference:"1:1.8.13.1~dfsg1-3+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-doc", reference:"1:1.8.13.1~dfsg1-3+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-mobile", reference:"1:1.8.13.1~dfsg1-3+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-modules", reference:"1:1.8.13.1~dfsg1-3+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-mp3", reference:"1:1.8.13.1~dfsg1-3+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-mysql", reference:"1:1.8.13.1~dfsg1-3+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-ooh323", reference:"1:1.8.13.1~dfsg1-3+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-voicemail", reference:"1:1.8.13.1~dfsg1-3+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-voicemail-imapstorage", reference:"1:1.8.13.1~dfsg1-3+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"asterisk-voicemail-odbcstorage", reference:"1:1.8.13.1~dfsg1-3+deb7u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
