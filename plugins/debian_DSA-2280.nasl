#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2280. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55625);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/02/16 15:31:55 $");

  script_cve_id("CVE-2011-1486", "CVE-2011-2511");
  script_bugtraq_id(47148, 48478);
  script_osvdb_id(72643, 73668);
  script_xref(name:"DSA", value:"2280");

  script_name(english:"Debian DSA-2280-1 : libvirt - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that libvirt, a library for interfacing with
different virtualization systems, is prone to an integer overflow
(CVE-2011-2511 ). Additionally, the stable version is prone to a
denial of service, because its error reporting is not thread-safe
(CVE-2011-1486 )."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=633630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=623222"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/libvirt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2280"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libvirt packages.

For the stable distribution (squeeze), these problems have been fixed
in version 0.8.3-5+squeeze2.

For the oldstable distribution (lenny), this problem has been fixed in
version 0.4.6-10+lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/20");
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
if (deb_check(release:"5.0", prefix:"libvirt", reference:"0.4.6-10+lenny2")) flag++;
if (deb_check(release:"6.0", prefix:"libvirt-bin", reference:"0.8.3-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libvirt-dev", reference:"0.8.3-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libvirt-doc", reference:"0.8.3-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libvirt0", reference:"0.8.3-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libvirt0-dbg", reference:"0.8.3-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"python-libvirt", reference:"0.8.3-5+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
