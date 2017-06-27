#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-493-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91360);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/06 20:03:51 $");

  script_cve_id("CVE-2015-8312", "CVE-2016-2860", "CVE-2016-4536");
  script_osvdb_id(136288, 136728);

  script_name(english:"Debian DLA-493-1 : openafs security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - CVE-2015-8312: Off-by-one error in afs_pioctl.c in
    OpenAFS before 1.6.16 might allow local users to cause a
    denial of service (memory overwrite and system crash)
    via a pioctl with an input buffer size of 4096 bytes.

  - CVE-2016-2860: The newEntry function in
    ptserver/ptprocs.c in OpenAFS before 1.6.17 allows
    remote authenticated users from foreign Kerberos realms
    to bypass intended access restrictions and create
    arbitrary groups as administrators by leveraging
    mishandling of the creator ID.

  - CVE-2016-4536: The client in OpenAFS before 1.6.17 does
    not properly initialize the (1) AFSStoreStatus, (2)
    AFSStoreVolumeStatus, (3) VldbListByAttributes, and (4)
    ListAddrByAttributes structures, which might allow
    remote attackers to obtain sensitive memory information
    by leveraging access to RPC call traffic.

For Debian 7 'Wheezy', these problems have been fixed in version
1.6.1-3+deb7u6.

We recommend that you upgrade your openafs packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/05/msg00045.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/openafs"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libafsauthent1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libafsrpc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkopenafs1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenafs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-openafs-kaserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-dbserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-fileserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-kpasswd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-modules-dkms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-modules-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/31");
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
if (deb_check(release:"7.0", prefix:"libafsauthent1", reference:"1.6.1-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libafsrpc1", reference:"1.6.1-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libkopenafs1", reference:"1.6.1-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libopenafs-dev", reference:"1.6.1-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libpam-openafs-kaserver", reference:"1.6.1-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-client", reference:"1.6.1-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-dbg", reference:"1.6.1-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-dbserver", reference:"1.6.1-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-doc", reference:"1.6.1-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-fileserver", reference:"1.6.1-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-fuse", reference:"1.6.1-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-kpasswd", reference:"1.6.1-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-krb5", reference:"1.6.1-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-modules-dkms", reference:"1.6.1-3+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-modules-source", reference:"1.6.1-3+deb7u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
