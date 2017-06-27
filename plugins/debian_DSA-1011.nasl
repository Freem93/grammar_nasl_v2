#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1011. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22553);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/26 15:53:37 $");

  script_cve_id("CVE-2005-4347", "CVE-2005-4418");
  script_osvdb_id(24049, 30403);
  script_xref(name:"DSA", value:"1011");

  script_name(english:"Debian DSA-1011-1 : kernel-patch-vserver - missing attribute support");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Debian vserver
support for Linux. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2005-4347
    Bjorn Steinbrink discovered that the chroot barrier is
    not set correctly with util-vserver which may result in
    unauthorised escapes from a vserver to the host system.

  This vulnerability is limited to the 2.4 kernel patch included in
  kernel-patch-vserver. The correction to this problem requires
  updating the util-vserver package as well and installing a new
  kernel built from the updated kernel-patch-vserver package.

  - CVE-2005-4418
    The default policy of util-vserver is set to trust all
    unknown capabilities instead of considering them as
    insecure."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=329087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=329090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-4347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-4418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1011"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the util-vserver and kernel-patch-vserver packages and build a
new kernel immediately.

The old stable distribution (woody) does not contain a
kernel-patch-vserver package.

For the stable distribution (sarge) this problem has been fixed in
version 1.9.5.5 of kernel-patch-vserver and in version
0.30.204-5sarge3 of util-vserver."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-patch-vserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:util-vserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"kernel-patch-vserver", reference:"1.9.5.5")) flag++;
if (deb_check(release:"3.1", prefix:"util-vserver", reference:"0.30.204-5sarge3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
