#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2168. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52031);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/02/16 15:31:54 $");

  script_cve_id("CVE-2011-0430", "CVE-2011-0431");
  script_xref(name:"DSA", value:"2168");

  script_name(english:"Debian DSA-2168-1 : openafs - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities were discovered the distributed filesystem AFS :

  - CVE-2011-0430
    Andrew Deason discovered that a double free in the Rx
    server process could lead to denial of service or the
    execution of arbitrary code.

  - CVE-2011-0431
    It was discovered that insufficient error handling in
    the kernel module could lead to denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0430"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/openafs"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2168"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openafs packages. Note that in order to apply this
security update, you must rebuild the OpenAFS kernel module. 

For the oldstable distribution (lenny), this problem has been fixed in
version 1.4.7.dfsg1-6+lenny4. Due to a technical problem with the
buildd infrastructure the update is not yet available, but will be
installed into the archive soon.

For the stable distribution (squeeze), this problem has been fixed in
version 1.4.12.1+dfsg-4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"openafs", reference:"1.4.7.dfsg1-6+lenny4")) flag++;
if (deb_check(release:"6.0", prefix:"libopenafs-dev", reference:"1.4.12.1+dfsg-4")) flag++;
if (deb_check(release:"6.0", prefix:"libpam-openafs-kaserver", reference:"1.4.12.1+dfsg-4")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-client", reference:"1.4.12.1+dfsg-4")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-dbg", reference:"1.4.12.1+dfsg-4")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-dbserver", reference:"1.4.12.1+dfsg-4")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-doc", reference:"1.4.12.1+dfsg-4")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-fileserver", reference:"1.4.12.1+dfsg-4")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-kpasswd", reference:"1.4.12.1+dfsg-4")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-krb5", reference:"1.4.12.1+dfsg-4")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-modules-dkms", reference:"1.4.12.1+dfsg-4")) flag++;
if (deb_check(release:"6.0", prefix:"openafs-modules-source", reference:"1.4.12.1+dfsg-4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
