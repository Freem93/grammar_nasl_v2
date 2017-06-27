#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-27-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82175);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/05 14:49:54 $");

  script_cve_id("CVE-2014-0207", "CVE-2014-0237", "CVE-2014-0238", "CVE-2014-3478", "CVE-2014-3479", "CVE-2014-3480", "CVE-2014-3487");
  script_bugtraq_id(67759, 67765, 68120, 68238, 68239, 68241, 68243);
  script_osvdb_id(107559, 107560, 108463, 108464, 108465, 108466, 108467);

  script_name(english:"Debian DLA-27-1 : file security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fix various denial of service attacks :

CVE-2014-3487

The cdf_read_property_info function does not properly validate a
stream offset, which allows remote attackers to cause a denial of
service (application crash) via a crafted CDF file.

CVE-2014-3480

The cdf_count_chain function in cdf.c in does not properly validate
sector-count data, which allows remote attackers to cause a denial of
service (application crash) via a crafted CDF file.

CVE-2014-3479

The cdf_check_stream_offset function in cdf.c relies on incorrect
sector-size data, which allows remote attackers to cause a denial of
service (application crash) via a crafted stream offset in a CDF file.

CVE-2014-3478

Buffer overflow in the mconvert function in softmagic.c allows remote
attackers to cause a denial of service (application crash) via a
crafted Pascal string in a FILE_PSTRING conversion.

CVE-2014-0238

The cdf_read_property_info function in cdf.c allows remote attackers
to cause a denial of service (infinite loop or out-of-bounds memory
access) via a vector that (1) has zero length or (2) is too long.

CVE-2014-0237

The cdf_unpack_summary_info function in cdf.c allows remote attackers
to cause a denial of service (performance degradation) by triggering
many file_printf calls.

CVE-2014-0207

The cdf_read_short_sector function in cdf.c allows remote attackers to
cause a denial of service (assertion failure and application exit) via
a crafted CDF file.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2014/07/msg00013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/file"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagic-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagic1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-magic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-magic-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/31");
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
if (deb_check(release:"6.0", prefix:"file", reference:"5.04-5+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"libmagic-dev", reference:"5.04-5+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"libmagic1", reference:"5.04-5+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"python-magic", reference:"5.04-5+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"python-magic-dbg", reference:"5.04-5+squeeze6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
