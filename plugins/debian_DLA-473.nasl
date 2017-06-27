#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-473-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91135);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/10/10 14:05:02 $");

  script_cve_id("CVE-2016-4476", "CVE-2016-4477");

  script_name(english:"Debian DLA-473-1 : wpa security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability was found in how hostapd and wpa_supplicant writes the
configuration file update for the WPA/WPA2 passphrase parameter. If
this parameter has been updated to include control characters either
through a WPS operation (CVE-2016-4476) or through local configuration
change over the wpa_supplicant control interface (CVE-2016-4477), the
resulting configuration file may prevent the hostapd and
wpa_supplicant from starting when the updated file is used. In
addition for wpa_supplicant, it may be possible to load a local
library file and execute code from there with the same privileges
under which the wpa_supplicant process runs.

CVE-2016-4476 hostapd 0.6.7 through 2.5 and wpa_supplicant 0.6.7
through 2.5 do not reject \n and \r characters in passphrase
parameters, which allows remote attackers to cause a denial of service
(daemon outage) via a crafted WPS operation.

CVE-2016-4477 wpa_supplicant 0.4.0 through 2.5 does not reject \n and
\r characters in passphrase parameters, which allows local users to
trigger arbitrary library loading and consequently gain privileges, or
cause a denial of service (daemon outage), via a crafted (1) SET, (2)
SET_CRED, or (3) SET_NETWORK command.

For Debian 7 'Wheezy', these problems have been fixed in version
1.0-3+deb7u4.

We recommend that you upgrade your wpa packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/05/msg00025.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/wpa"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hostapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wpagui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wpasupplicant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wpasupplicant-udeb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/16");
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
if (deb_check(release:"7.0", prefix:"hostapd", reference:"1.0-3+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"wpagui", reference:"1.0-3+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"wpasupplicant", reference:"1.0-3+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"wpasupplicant-udeb", reference:"1.0-3+deb7u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
