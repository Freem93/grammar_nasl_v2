#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2810. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71221);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/16 15:43:10 $");

  script_cve_id("CVE-2013-4164");
  script_bugtraq_id(63873);
  script_xref(name:"DSA", value:"2810");

  script_name(english:"Debian DSA-2810-1 : ruby1.9.1 - heap overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Charlie Somerville discovered that Ruby incorrectly handled floating
point number conversion. If an application using Ruby accepted
untrusted input strings and converted them to floating point numbers,
an attacker able to provide such input could cause the application to
crash or, possibly, execute arbitrary code with the privileges of the
application."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=730178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/ruby1.9.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2810"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ruby1.9.1 packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 1.9.2.0-2+deb6u2.

For the stable distribution (wheezy), this problem has been fixed in
version 1.9.3.194-8.1+deb7u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.9.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"ruby1.9.1", reference:"1.9.2.0-2+deb6u2")) flag++;
if (deb_check(release:"7.0", prefix:"libruby1.9.1", reference:"1.9.3.194-8.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libruby1.9.1-dbg", reference:"1.9.3.194-8.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libtcltk-ruby1.9.1", reference:"1.9.3.194-8.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"ri1.9.1", reference:"1.9.3.194-8.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"ruby1.9.1", reference:"1.9.3.194-8.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"ruby1.9.1-dev", reference:"1.9.3.194-8.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"ruby1.9.1-examples", reference:"1.9.3.194-8.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"ruby1.9.1-full", reference:"1.9.3.194-8.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"ruby1.9.3", reference:"1.9.3.194-8.1+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
