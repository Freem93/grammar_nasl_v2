#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-869-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97964);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/27 13:24:15 $");

  script_cve_id("CVE-2017-5613", "CVE-2017-5614", "CVE-2017-5615", "CVE-2017-5616");
  script_osvdb_id(150645, 150647, 150648, 150649);

  script_name(english:"Debian DLA-869-1 : cgiemail security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The cPanel Security Team discovered several security vulnerabilities
in cgiemail, a CGI program used to create HTML forms for sending 
mails :

CVE-2017-5613

A format string injection vulnerability allowed to supply arbitrary
format strings to cgiemail and cgiecho. A local attacker with
permissions to provide a cgiemail template could use this
vulnerability to execute code as webserver user. Format strings in
cgiemail tempaltes are now restricted to simple %s, %U and %H
sequences.

CVE-2017-5614

An open redirect vulnerability in cgiemail and cgiecho binaries could
be exploited by a local attacker to force redirect to an arbitrary
URL. These redirects are now limited to the domain that handled the
request.

CVE-2017-5615

A vulnerability in cgiemail and cgiecho binaries allowed injection of
additional HTTP headers. Newline characters are now stripped from the
redirect location to protect against this.

CVE-2017-5616

Missing escaping of the addendum parameter lead to a reflected
cross-site (XSS) vulnerability in cgiemail and cgiecho binaries. The
output is now html escaped.

For Debian 7 'Wheezy', these problems have been fixed in version
1.6-37+deb7u1.

We recommend that you upgrade your cgiemail packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/03/msg00026.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/cgiemail"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected cgiemail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cgiemail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"cgiemail", reference:"1.6-37+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
