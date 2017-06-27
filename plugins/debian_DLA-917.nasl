#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-917-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99674);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/26 13:35:46 $");

  script_cve_id("CVE-2015-8270", "CVE-2015-8271", "CVE-2015-8272");
  script_osvdb_id(132732, 132733, 132734);

  script_name(english:"Debian DLA-917-1 : rtmpdump security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were found in rtmpdump and the librtmp
library.

CVE-2015-8270

A bug in AMF3ReadString in librtmp can cause a denial of service via
application crash to librtmp users that talk to a malicious server.

CVE-2015-8271

The AMF3_Decode function in librtmp doesn't properly validate its
input, which can lead to arbitrary code execution when talking to a
malicious attacker.

CVE-2015-8272

A bug in rtmpsrv can lead to a crash when talking to a malicious
client.

For Debian 7 'Wheezy', these problems have been fixed in version
2.4+20111222.git4e06e21-1+deb7u1.

We recommend that you upgrade your rtmpdump packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/04/msg00036.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/rtmpdump"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected librtmp-dev, librtmp0, and rtmpdump packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librtmp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librtmp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rtmpdump");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/26");
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
if (deb_check(release:"7.0", prefix:"librtmp-dev", reference:"2.4+20111222.git4e06e21-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"librtmp0", reference:"2.4+20111222.git4e06e21-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"rtmpdump", reference:"2.4+20111222.git4e06e21-1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
