#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-126-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82109);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/12/02 20:08:16 $");

  script_cve_id("CVE-2014-9380", "CVE-2014-9381");
  script_bugtraq_id(71691, 71693);

  script_name(english:"Debian DLA-126-1 : ettercap security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Patches a bunch of security vulnerabilities :

  - CVE-2014-9380 (Buffer over-read)

  - CVE-2014-9381 (Signedness error) See:
    https://www.obrela.com/home/security-labs/advisories/osi
    -advisory-osi-1402/ Patches taken from upstream

  - 6b196e011fa456499ed4650a360961a2f1323818 pull/608

  - 31b937298c8067e6b0c3217c95edceb983dfc4a2 pull/609 Thanks
    to Nick Sampanis <n.sampanis@obrela.com> who is
    responsible for both finding and repairing these issues.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2014/12/msg00028.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/ettercap"
  );
  # https://www.obrela.com/home/security-labs/advisories/osi-advisory-osi-1402/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?55000fec"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ettercap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ettercap-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ettercap-gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/29");
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
if (deb_check(release:"6.0", prefix:"ettercap", reference:"1:0.7.3-2.1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"ettercap-common", reference:"1:0.7.3-2.1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"ettercap-gtk", reference:"1:0.7.3-2.1+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
