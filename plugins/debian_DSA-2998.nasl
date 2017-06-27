#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2998. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77035);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/05 16:01:11 $");

  script_cve_id("CVE-2014-3505", "CVE-2014-3506", "CVE-2014-3507", "CVE-2014-3508", "CVE-2014-3509", "CVE-2014-3510", "CVE-2014-3511", "CVE-2014-3512", "CVE-2014-5139");
  script_bugtraq_id(69075, 69076, 69077, 69078, 69079, 69081, 69082, 69083, 69084);
  script_osvdb_id(109891, 109892, 109893, 109894, 109895, 109896, 109897, 109898, 109902);
  script_xref(name:"DSA", value:"2998");

  script_name(english:"Debian DSA-2998-1 : openssl - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been identified in OpenSSL, a Secure
Sockets Layer toolkit, that may result in denial of service
(application crash, large memory consumption), information leak,
protocol downgrade. Additionally, a buffer overrun affecting only
applications explicitly set up for SRP has been fixed (CVE-2014-3512
).

Detailed descriptions of the vulnerabilities can be found at:
www.openssl.org/news/secadv/20140806.txt

It's important that you upgrade the libssl1.0.0 package and not just
the openssl package.

All applications linked to openssl need to be restarted. You can use
the 'checkrestart' tool from the debian-goodies package to detect
affected programs. Alternatively, you may reboot your system."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openssl.org/news/secadv/20140806.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/openssl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2998"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssl packages.

For the stable distribution (wheezy), these problems have been fixed
in version 1.0.1e-2+deb7u12."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/07");
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
if (deb_check(release:"7.0", prefix:"libssl-dev", reference:"1.0.1e-2+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libssl-doc", reference:"1.0.1e-2+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libssl1.0.0", reference:"1.0.1e-2+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"libssl1.0.0-dbg", reference:"1.0.1e-2+deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"openssl", reference:"1.0.1e-2+deb7u12")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
