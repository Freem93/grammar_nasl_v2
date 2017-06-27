#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3495. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89046);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/10 14:14:52 $");

  script_cve_id("CVE-2016-2054", "CVE-2016-2055", "CVE-2016-2056", "CVE-2016-2057", "CVE-2016-2058");
  script_xref(name:"DSA", value:"3495");

  script_name(english:"Debian DSA-3495-1 : xymon - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Markus Krell discovered that xymon, a network- and
applications-monitoring system, was vulnerable to the following
security issues :

  - CVE-2016-2054
    The incorrect handling of user-supplied input in the
    'config' command can trigger a stack-based buffer
    overflow, resulting in denial of service (via
    application crash) or remote code execution.

  - CVE-2016-2055
    The incorrect handling of user-supplied input in the
    'config' command can lead to an information leak by
    serving sensitive configuration files to a remote user.

  - CVE-2016-2056
    The commands handling password management do not
    properly validate user-supplied input, and are thus
    vulnerable to shell command injection by a remote user.

  - CVE-2016-2057
    Incorrect permissions on an internal queuing system
    allow a user with a local account on the xymon master
    server to bypass all network-based access control lists,
    and thus inject messages directly into xymon.

  - CVE-2016-2058
    Incorrect escaping of user-supplied input in status
    webpages can be used to trigger reflected cross-site
    scripting attacks."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2055"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2057"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/xymon"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3495"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xymon packages.

For the stable distribution (jessie), these problems have been fixed
in version 4.3.17-6+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xymon");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/01");
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
if (deb_check(release:"8.0", prefix:"xymon", reference:"4.3.17-6+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xymon-client", reference:"4.3.17-6+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
