#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-553-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92474);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2017/01/16 16:05:33 $");

  script_cve_id("CVE-2016-5387");
  script_osvdb_id(141669);
  script_xref(name:"IAVA", value:"2017-A-0010");

  script_name(english:"Debian DLA-553-1 : apache2 security update (httpoxy)");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Scott Geary of VendHQ discovered that the Apache HTTPD server used the
value of the Proxy header from HTTP requests to initialize the
HTTP_PROXY environment variable for CGI scripts, which in turn was
incorrectly used by certain HTTP client implementations to configure
the proxy for outgoing HTTP requests. A remote attacker could possibly
use this flaw to redirect HTTP requests performed by a CGI script to
an attacker-controlled proxy via a malicious HTTP request.

For Debian 7 'Wheezy', this problem has been fixed in version
2.2.22-13+deb7u7.

We recommend that you upgrade your apache2 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/07/msg00015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/apache2"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-mpm-event");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-mpm-itk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-mpm-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-mpm-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-prefork-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-suexec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-suexec-custom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-threaded-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2.2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2.2-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/20");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/21");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"apache2", reference:"2.2.22-13+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-dbg", reference:"2.2.22-13+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-doc", reference:"2.2.22-13+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-mpm-event", reference:"2.2.22-13+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-mpm-itk", reference:"2.2.22-13+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-mpm-prefork", reference:"2.2.22-13+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-mpm-worker", reference:"2.2.22-13+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-prefork-dev", reference:"2.2.22-13+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-suexec", reference:"2.2.22-13+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-suexec-custom", reference:"2.2.22-13+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-threaded-dev", reference:"2.2.22-13+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"apache2-utils", reference:"2.2.22-13+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"apache2.2-bin", reference:"2.2.22-13+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"apache2.2-common", reference:"2.2.22-13+deb7u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
