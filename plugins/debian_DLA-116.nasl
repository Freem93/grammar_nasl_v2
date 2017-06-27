#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-116-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82099);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/12/02 20:08:16 $");

  script_cve_id("CVE-2014-9293", "CVE-2014-9294", "CVE-2014-9295", "CVE-2014-9296");
  script_bugtraq_id(71757, 71758, 71761, 71762);
  script_osvdb_id(116066, 116067, 116068, 116069, 116070, 116074);

  script_name(english:"Debian DLA-116-1 : ntp security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in the ntp package, an
implementation of the Network Time Protocol.

CVE-2014-9293

ntpd generated a weak key for its internal use, with full
administrative privileges. Attackers could use this key to reconfigure
ntpd (or to exploit other vulnerabilities).

CVE-2014-9294

The ntp-keygen utility generated weak MD5 keys with insufficient
entropy.

CVE-2014-9295

ntpd had several buffer overflows (both on the stack and in the data
section), allowing remote authenticated attackers to crash ntpd or
potentially execute arbitrary code.

CVE-2014-9296

The general packet processing function in ntpd did not handle an error
case correctly.

The default ntpd configuration in Debian restricts access to localhost
(and possible the adjacent network in case of IPv6).

Keys explicitly generated by 'ntp-keygen -M' should be regenerated.

For the oldstable distribution (squeeze), these problems have been
fixed in version 4.2.6.p2+dfsg-1+deb6u1.

We recommend that you upgrade your heirloom-mailx packages.

Thanks to the Florian Weimer for the Red Hat security update.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2014/12/msg00018.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/ntp"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected ntp, ntp-doc, and ntpdate packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntpdate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
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
if (deb_check(release:"6.0", prefix:"ntp", reference:"4.2.6.p2+dfsg-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"ntp-doc", reference:"4.2.6.p2+dfsg-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"ntpdate", reference:"4.2.6.p2+dfsg-1+deb6u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
