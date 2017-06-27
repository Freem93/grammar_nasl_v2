#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-755-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95955);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/02/28 14:42:19 $");

  script_cve_id("CVE-2015-8979");
  script_osvdb_id(149181);

  script_name(english:"Debian DLA-755-1 : dcmtk security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"At several places in the code a wrong length of ACSE data structures
received over the network can cause overflows or underflows when
processing those data structures. Related checks have been added at
various places in order to prevent such (possible) attacks. Thanks to
Kevin Basista for the report.

The bug will indeed affect all DCMTK-based server applications that
accept incoming DICOM network connections that are using the
dcmtk-3.6.0 and earlier versions.

(From: http://zeroscience.mk/en/vulnerabilities/ZSL-2016-5384.php)

For Debian 7 'Wheezy', these problems have been fixed in version
3.6.0-12+deb7u1.

We recommend that you upgrade your dcmtk packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://zeroscience.mk/en/vulnerabilities/ZSL-2016-5384.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/12/msg00031.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/dcmtk"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dcmtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dcmtk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dcmtk-www");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdcmtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdcmtk2-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/21");
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
if (deb_check(release:"7.0", prefix:"dcmtk", reference:"3.6.0-12+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"dcmtk-doc", reference:"3.6.0-12+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"dcmtk-www", reference:"3.6.0-12+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libdcmtk2", reference:"3.6.0-12+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libdcmtk2-dev", reference:"3.6.0-12+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
