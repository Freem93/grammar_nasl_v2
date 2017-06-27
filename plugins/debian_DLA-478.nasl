#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-478-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91173);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/12/06 20:03:51 $");

  script_cve_id("CVE-2016-4051", "CVE-2016-4052", "CVE-2016-4053", "CVE-2016-4054", "CVE-2016-4554", "CVE-2016-4555", "CVE-2016-4556");
  script_osvdb_id(137402, 137403, 137404, 137405, 138133, 138134);

  script_name(english:"Debian DLA-478-1 : squid3 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security issues have been discovered in the Squid caching
proxy.

CVE-2016-4051

CESG and Yuriy M. Kaminskiy discovered that Squid cachemgr.cgi was
vulnerable to a buffer overflow when processing remotely supplied
inputs relayed through Squid.

CVE-2016-4052 

CESG discovered that a buffer overflow made Squid vulnerable to a
Denial of Service (DoS) attack when processing ESI responses.

CVE-2016-4053

CESG found that Squid was vulnerable to public information disclosure
of the server stack layout when processing ESI responses.

CVE-2016-4054

CESG discovered that Squid was vulnerable to remote code execution
when processing ESI responses.

CVE-2016-4554

Jianjun Chen found that Squid was vulnerable to a header smuggling
attack that could lead to cache poisoning and to bypass of same-origin
security policy in Squid and some client browsers.

CVE-2016-4555 and CVE-2016-4556

'bfek-18' and '@vftable' found that Squid was vulnerable to a Denial
of Service (DoS) attack when processing ESI responses, due to
incorrect pointer handling and reference counting.

For Debian 7 'Wheezy', these issues have been fixed in squid3 version
3.1.20-2.2+deb7u5. We recommend you to upgrade your squid3 packages.

Learn more about the Debian Long Term Support (LTS) Project and how to
apply these updates at: https://wiki.debian.org/LTS/

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/05/msg00028.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/squid3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.debian.org/LTS/"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid3-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squidclient");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/17");
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
if (deb_check(release:"7.0", prefix:"squid-cgi", reference:"3.1.20-2.2+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"squid3", reference:"3.1.20-2.2+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"squid3-common", reference:"3.1.20-2.2+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"squid3-dbg", reference:"3.1.20-2.2+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"squidclient", reference:"3.1.20-2.2+deb7u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
