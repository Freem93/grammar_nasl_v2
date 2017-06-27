#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-51-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82198);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/06 13:33:34 $");

  script_cve_id("CVE-2014-4617");
  script_bugtraq_id(68156);
  script_osvdb_id(108367);

  script_name(english:"Debian DLA-51-1 : gnupg2 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jean-Rene Reinhard, Olivier Levillain and Florian Maury reported that
GnuPG, the GNU Privacy Guard, did not properly parse certain garbled
compressed data packets. A remote attacker could use this flaw to
mount a denial of service against GnuPG by triggering an infinite
loop.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2014/09/msg00007.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/gnupg2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected gnupg-agent, gnupg2, and gpgsm packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnupg-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnupg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gpgsm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
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
if (deb_check(release:"6.0", prefix:"gnupg-agent", reference:"2.0.14-2+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"gnupg2", reference:"2.0.14-2+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"gpgsm", reference:"2.0.14-2+squeeze3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
