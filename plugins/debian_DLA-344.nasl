#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-344-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86952);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/04/28 18:15:20 $");

  script_cve_id("CVE-2015-7183");
  script_osvdb_id(129799);

  script_name(english:"Debian DLA-344-1 : nspr security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google security engineer Ryan Sleevi found a vulnerability in the
NetScape Portable Runtime Library (NSPR). NSPR allocated memory
without specific checks, making it possible for remote attackers to
cause a Denial of Service or execute arbitrary code.

For Debian 6 'Squeeze', this issue have been fixed in nspr version
4.8.6-1+squeeze3. We recommend that you upgrade your nspr packages.

Learn more about the Debian Long Term Support (LTS) Project and how to
apply these updates at: https://wiki.debian.org/LTS/

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/11/msg00006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/nspr"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.debian.org/LTS/"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnspr4-0d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnspr4-0d-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnspr4-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/20");
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
if (deb_check(release:"6.0", prefix:"libnspr4-0d", reference:"4.8.6-1+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libnspr4-0d-dbg", reference:"4.8.6-1+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libnspr4-dev", reference:"4.8.6-1+squeeze3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
