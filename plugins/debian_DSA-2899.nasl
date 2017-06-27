#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2899. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73441);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:43:11 $");

  script_cve_id("CVE-2014-0159", "CVE-2014-2852");
  script_bugtraq_id(66776);
  script_osvdb_id(105720, 105964);
  script_xref(name:"DSA", value:"2899");

  script_name(english:"Debian DSA-2899-1 : openafs - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Michael Meffie discovered that in OpenAFS, a distributed filesystem,
an attacker with the ability to connect to an OpenAFS fileserver can
trigger a buffer overflow, crashing the fileserver, and potentially
permitting the execution of arbitrary code.

In addition, this update addresses a minor denial of service issue:
the listener thread of the server will hang for about one second when
receiving an invalid packet, giving the opportunity to slow down the
server to an unusable state by sending such packets."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/openafs"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/openafs"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2899"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openafs packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 1.4.12.1+dfsg-4+squeeze3.

For the stable distribution (wheezy), this problem has been fixed in
version 1.6.1-3+deb7u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libopenafs-dev", reference:"1.4.12.1+dfsg-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libpam-openafs-kaserver", reference:"1.4.12.1+dfsg-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-client", reference:"1.4.12.1+dfsg-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-dbg", reference:"1.4.12.1+dfsg-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-dbserver", reference:"1.4.12.1+dfsg-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-doc", reference:"1.4.12.1+dfsg-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-fileserver", reference:"1.4.12.1+dfsg-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-kpasswd", reference:"1.4.12.1+dfsg-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-krb5", reference:"1.4.12.1+dfsg-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-modules-dkms", reference:"1.4.12.1+dfsg-4+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-modules-source", reference:"1.4.12.1+dfsg-4+squeeze3")) flag++;
if (deb_check(release:"7.0", prefix:"libafsauthent1", reference:"1.6.1-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libafsrpc1", reference:"1.6.1-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libkopenafs1", reference:"1.6.1-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libopenafs-dev", reference:"1.6.1-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libpam-openafs-kaserver", reference:"1.6.1-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-client", reference:"1.6.1-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-dbg", reference:"1.6.1-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-dbserver", reference:"1.6.1-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-doc", reference:"1.6.1-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-fileserver", reference:"1.6.1-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-fuse", reference:"1.6.1-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-kpasswd", reference:"1.6.1-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-krb5", reference:"1.6.1-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-modules-dkms", reference:"1.6.1-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"openafs-modules-source", reference:"1.6.1-3+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
