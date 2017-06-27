#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3569. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90928);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/10/10 14:14:53 $");

  script_cve_id("CVE-2015-8312", "CVE-2016-2860");
  script_xref(name:"DSA", value:"3569");

  script_name(english:"Debian DSA-3569-1 : openafs - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities were discovered in openafs, an implementation of
the distributed filesystem AFS. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2015-8312
    Potential denial of service caused by a bug in the
    pioctl logic allowing a local user to overrun a kernel
    buffer with a single NUL byte.

  - CVE-2016-2860
    Peter Iannucci discovered that users from foreign
    Kerberos realms can create groups as if they were
    administrators."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/openafs"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3569"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openafs packages.

For the stable distribution (jessie), these problems have been fixed
in version 1.6.9-2+deb8u5."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/06");
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
if (deb_check(release:"8.0", prefix:"libafsauthent1", reference:"1.6.9-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libafsrpc1", reference:"1.6.9-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libkopenafs1", reference:"1.6.9-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libopenafs-dev", reference:"1.6.9-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libpam-openafs-kaserver", reference:"1.6.9-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-client", reference:"1.6.9-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-dbg", reference:"1.6.9-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-dbserver", reference:"1.6.9-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-doc", reference:"1.6.9-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-fileserver", reference:"1.6.9-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-fuse", reference:"1.6.9-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-kpasswd", reference:"1.6.9-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-krb5", reference:"1.6.9-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-modules-dkms", reference:"1.6.9-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"openafs-modules-source", reference:"1.6.9-2+deb8u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
