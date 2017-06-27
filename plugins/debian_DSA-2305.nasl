#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2305. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56231);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2011-0762", "CVE-2011-2189");
  script_bugtraq_id(46617);
  script_osvdb_id(73340, 76805);
  script_xref(name:"DSA", value:"2305");

  script_name(english:"Debian DSA-2305-1 : vsftpd - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two security issue have been discovered that affect vsftpd, a
lightweight, efficient FTP server written for security.

  - CVE-2011-2189
    It was discovered that Linux kernels < 2.6.35 are
    considerably slower in releasing than in the creation of
    network namespaces. As a result of this and because
    vsftpd is using this feature as a security enhancement
    to provide network isolation for connections, it is
    possible to cause denial of service conditions due to
    excessive memory allocations by the kernel. This is
    technically no vsftpd flaw, but a kernel issue. However,
    this feature has legitimate use cases and backporting
    the specific kernel patch is too intrusive.
    Additionally, a local attacker requires the
    CAP_SYS_ADMIN capability to abuse this functionality.
    Therefore, as a fix, a kernel version check has been
    added to vsftpd in order to disable this feature for
    kernels < 2.6.35.

  - CVE-2011-0762
    Maksymilian Arciemowicz discovered that vsftpd is
    incorrectly handling certain glob expressions in STAT
    commands. This allows a remote authenticated attacker to
    conduct denial of service attacks (excessive CPU and
    process slot exhaustion) via crafted STAT commands."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=622741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=629373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/vsftpd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2305"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the vsftpd packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 2.0.7-1+lenny1.

For the stable distribution (squeeze), this problem has been fixed in
version 2.3.2-3+squeeze2. Please note that CVE-2011-2189 does not
affect the lenny version."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vsftpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"vsftpd", reference:"2.0.7-1+lenny1")) flag++;
if (deb_check(release:"6.0", prefix:"vsftpd", reference:"2.3.2-3+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
