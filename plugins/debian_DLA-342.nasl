#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-342-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86920);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/04/28 18:15:20 $");

  script_cve_id("CVE-2015-3282", "CVE-2015-3283", "CVE-2015-3285", "CVE-2015-6587", "CVE-2015-7762", "CVE-2015-7763");
  script_osvdb_id(125605, 125606, 125608, 126085, 129562, 129563);

  script_name(english:"Debian DLA-342-1 : openafs security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been found and solved in the distributed
file system OpenAFS :

CVE-2015-3282

vos leaked stack data clear on the wire when updating vldb entries.

CVE-2015-3283

OpenAFS allowed remote attackers to spoof bos commands via unspecified
vectors.

CVE-2015-3285

pioctl wrongly used the pointer related to the RPC, allowing local
users to cause a denial of service (memory corruption and kernel
panic) via a crafted OSD FS command.

CVE-2015-6587

vlserver allowed remote authenticated users to cause a denial of
service (out-of-bounds read and crash) via a crafted regular
expression in a VL_ListAttributesN2 RPC.

CVE-2015-7762 and CVE-2015-7763 ('Tattletale')

John Stumpo found that Rx ACK packets leaked plaintext of packets
previously processed.

For Debian 6 'Squeeze', these problems have been fixed in openafs
version 1.4.12.1+dfsg-4+squeeze4.

We recommend that you upgrade your OpenAFS packages.

Learn more about the Debian Long Term Support (LTS) Project and how to
apply these updates at: https://wiki.debian.org/LTS/

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/11/msg00004.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/openafs"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.debian.org/LTS/"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenafs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-openafs-kaserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-dbserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-fileserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-kpasswd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-modules-dkms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs-modules-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/19");
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
if (deb_check(release:"6.0", prefix:"libopenafs-dev", reference:"1.4.12.1+dfsg-4+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libpam-openafs-kaserver", reference:"1.4.12.1+dfsg-4+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-client", reference:"1.4.12.1+dfsg-4+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-dbg", reference:"1.4.12.1+dfsg-4+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-dbserver", reference:"1.4.12.1+dfsg-4+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-doc", reference:"1.4.12.1+dfsg-4+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-fileserver", reference:"1.4.12.1+dfsg-4+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-kpasswd", reference:"1.4.12.1+dfsg-4+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-krb5", reference:"1.4.12.1+dfsg-4+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-modules-dkms", reference:"1.4.12.1+dfsg-4+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-modules-source", reference:"1.4.12.1+dfsg-4+squeeze4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
