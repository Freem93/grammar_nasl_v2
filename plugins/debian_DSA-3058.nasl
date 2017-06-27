#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3058. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78695);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/16 15:48:48 $");

  script_cve_id("CVE-2014-3684");
  script_bugtraq_id(70242);
  script_xref(name:"DSA", value:"3058");

  script_name(english:"Debian DSA-3058-1 : torque - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chad Vizino reported a vulnerability in torque, a PBS-derived batch
processing queueing system. A non-root user could exploit the flaw in
the tm_adopt() library call to kill any process, including root-owned
ones on any node in a job."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=763922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/torque"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-3058"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the torque packages.

For the stable distribution (wheezy), this problem has been fixed in
version 2.4.16+dfsg-1+deb7u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:torque");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/28");
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
if (deb_check(release:"7.0", prefix:"libtorque2", reference:"2.4.16+dfsg-1+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libtorque2-dev", reference:"2.4.16+dfsg-1+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"torque-client", reference:"2.4.16+dfsg-1+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"torque-client-x11", reference:"2.4.16+dfsg-1+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"torque-common", reference:"2.4.16+dfsg-1+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"torque-mom", reference:"2.4.16+dfsg-1+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"torque-pam", reference:"2.4.16+dfsg-1+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"torque-scheduler", reference:"2.4.16+dfsg-1+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"torque-server", reference:"2.4.16+dfsg-1+deb7u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
