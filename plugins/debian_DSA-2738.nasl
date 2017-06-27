#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2738. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69398);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:43 $");

  script_cve_id("CVE-2013-1821", "CVE-2013-4073");
  script_bugtraq_id(58141, 60843);
  script_osvdb_id(90587, 94628);
  script_xref(name:"DSA", value:"2738");

  script_name(english:"Debian DSA-2738-1 : ruby1.9.1 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the interpreter for
the Ruby language, which may lead to denial of service and other
security problems. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2013-1821
    Ben Murphy discovered that unrestricted entity expansion
    in REXML can lead to a Denial of Service by consuming
    all host memory.

  - CVE-2013-4073
    William (B.J.) Snow Orvis discovered a vulnerability in
    the hostname checking in Ruby's SSL client that could
    allow man-in-the-middle attackers to spoof SSL servers
    via valid certificate issued by a trusted certification
    authority."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=702525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=714543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/ruby1.9.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2738"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ruby1.9.1 packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 1.9.2.0-2+deb6u1.

For the stable distribution (wheezy), these problems have been fixed
in version 1.9.3.194-8.1+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.9.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"ruby1.9.1", reference:"1.9.2.0-2+deb6u1")) flag++;
if (deb_check(release:"7.0", prefix:"libruby1.9.1", reference:"1.9.3.194-8.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libruby1.9.1-dbg", reference:"1.9.3.194-8.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libtcltk-ruby1.9.1", reference:"1.9.3.194-8.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ri1.9.1", reference:"1.9.3.194-8.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ruby1.9.1", reference:"1.9.3.194-8.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ruby1.9.1-dev", reference:"1.9.3.194-8.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ruby1.9.1-examples", reference:"1.9.3.194-8.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ruby1.9.1-full", reference:"1.9.3.194-8.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ruby1.9.3", reference:"1.9.3.194-8.1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
