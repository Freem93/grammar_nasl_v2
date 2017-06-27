#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2952. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74374);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id("CVE-2014-1453", "CVE-2014-3000", "CVE-2014-3880");
  script_bugtraq_id(66726, 67153);
  script_osvdb_id(106442);
  script_xref(name:"DSA", value:"2952");

  script_name(english:"Debian DSA-2952-1 : kfreebsd-9 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the FreeBSD kernel
that may lead to a denial of service or possibly disclosure of kernel
memory. The Common Vulnerabilities and Exposures project identifies
the following problems :

  - CVE-2014-1453
    A remote, authenticated attacker could cause the NFS
    server become deadlocked, resulting in a denial of
    service.

  - CVE-2014-3000 :
    An attacker who can send a series of specifically
    crafted packets with a connection could cause a denial
    of service situation by causing the kernel to crash.

  Additionally, because the undefined on stack memory may be
  overwritten by other kernel threads, while difficult, it may be
  possible for an attacker to construct a carefully crafted attack to
  obtain portion of kernel memory via a connected socket. This may
  result in the disclosure of sensitive information such as login
  credentials, etc. before or even without crashing the system.

  - CVE-2014-3880
    A local attacker can trigger a kernel crash (triple
    fault) with potential data loss, related to the
    execve/fexecve system calls. Reported by Ivo De Decker."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-1453"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3880"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/kfreebsd-9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2952"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kfreebsd-9 packages.

For the stable distribution (wheezy), these problems have been fixed
in version 9.0-10+deb70.7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kfreebsd-9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9-486", reference:"9.0-10+deb70.7")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9-686", reference:"9.0-10+deb70.7")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9-686-smp", reference:"9.0-10+deb70.7")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9-amd64", reference:"9.0-10+deb70.7")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9-malta", reference:"9.0-10+deb70.7")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9-xen", reference:"9.0-10+deb70.7")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9.0-2", reference:"9.0-10+deb70.7")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9.0-2-486", reference:"9.0-10+deb70.7")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9.0-2-686", reference:"9.0-10+deb70.7")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9.0-2-686-smp", reference:"9.0-10+deb70.7")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9.0-2-amd64", reference:"9.0-10+deb70.7")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9.0-2-malta", reference:"9.0-10+deb70.7")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9.0-2-xen", reference:"9.0-10+deb70.7")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9-486", reference:"9.0-10+deb70.7")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9-686", reference:"9.0-10+deb70.7")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9-686-smp", reference:"9.0-10+deb70.7")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9-amd64", reference:"9.0-10+deb70.7")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9-malta", reference:"9.0-10+deb70.7")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9-xen", reference:"9.0-10+deb70.7")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9.0-2-486", reference:"9.0-10+deb70.7")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9.0-2-686", reference:"9.0-10+deb70.7")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9.0-2-686-smp", reference:"9.0-10+deb70.7")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9.0-2-amd64", reference:"9.0-10+deb70.7")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9.0-2-malta", reference:"9.0-10+deb70.7")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9.0-2-xen", reference:"9.0-10+deb70.7")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-source-9.0", reference:"9.0-10+deb70.7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
