#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-379-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87683);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/06 20:03:51 $");

  script_cve_id("CVE-2015-5252", "CVE-2015-5296", "CVE-2015-5299");
  script_osvdb_id(131936, 131937, 131938);

  script_name(english:"Debian DLA-379-1 : samba security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were found in Samba, a SMB/CIFS implementation
that provides a file, print, and login server.

CVE-2015-5252

Jan 'Yenya' Kasprzak and the Computer Systems Unit team at Faculty of
Informatics, Masaryk University, reported that samba wrongly verified
symlinks, making it possible to access resources outside the shared
path, under certain circumstances.

CVE-2015-5296

Stefan Metzmacher of SerNet and the Samba Team discovered that samba
did not ensure that signing was negotiated when a client established
an encrypted connection against a samba server.

CVE-2015-5299

Samba was vulnerable to a missing access control check in the VFS
shadow_copy2 module, that could allow unauthorized users to access
snapshots.

For Debian 6 'Squeeze', this issue has been fixed in samba version
2:3.5.6~dfsg-3squeeze13. We recommend you to upgrade your samba
packages.

Learn more about the Debian Long Term Support (LTS) Project and how to
apply these updates at: https://wiki.debian.org/LTS/

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/01/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/samba"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.debian.org/LTS/"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-smbpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-common-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:smbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:winbind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/04");
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
if (deb_check(release:"6.0", prefix:"libpam-smbpass", reference:"2:3.5.6~dfsg-3squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"libsmbclient", reference:"2:3.5.6~dfsg-3squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"libsmbclient-dev", reference:"2:3.5.6~dfsg-3squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"libwbclient0", reference:"2:3.5.6~dfsg-3squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"samba", reference:"2:3.5.6~dfsg-3squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"samba-common", reference:"2:3.5.6~dfsg-3squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"samba-common-bin", reference:"2:3.5.6~dfsg-3squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"samba-dbg", reference:"2:3.5.6~dfsg-3squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"samba-doc", reference:"2:3.5.6~dfsg-3squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"samba-doc-pdf", reference:"2:3.5.6~dfsg-3squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"samba-tools", reference:"2:3.5.6~dfsg-3squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"smbclient", reference:"2:3.5.6~dfsg-3squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"swat", reference:"2:3.5.6~dfsg-3squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"winbind", reference:"2:3.5.6~dfsg-3squeeze13")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
