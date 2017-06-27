#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-284-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85051);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/07/18 15:54:01 $");

  script_cve_id("CVE-2015-3183");
  script_bugtraq_id(75963);
  script_osvdb_id(123122);

  script_name(english:"Debian DLA-284-1 : apache2 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability has been found in the Apache HTTP Server.

CVE-2015-3183

Apache HTTP Server did not properly parse chunk headers, which allowed
remote attackers to conduct HTTP request smuggling via a crafted
request. This flaw relates to mishandling of large chunk-size values
and invalid chunk-extension characters in modules/http/http_filters.c.

For the squeeze distribution, these issues have been fixed in version
2.2.16-6+squeeze15 of apache2.

We recommend you to upgrade your apache2 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/07/msg00024.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/apache2"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"apache2", reference:"2.2.16-6+squeeze15")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-dbg", reference:"2.2.16-6+squeeze15")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-doc", reference:"2.2.16-6+squeeze15")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-mpm-event", reference:"2.2.16-6+squeeze15")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-mpm-itk", reference:"2.2.16-6+squeeze15")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-mpm-prefork", reference:"2.2.16-6+squeeze15")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-mpm-worker", reference:"2.2.16-6+squeeze15")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-prefork-dev", reference:"2.2.16-6+squeeze15")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-suexec", reference:"2.2.16-6+squeeze15")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-suexec-custom", reference:"2.2.16-6+squeeze15")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-threaded-dev", reference:"2.2.16-6+squeeze15")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-utils", reference:"2.2.16-6+squeeze15")) flag++;
if (deb_check(release:"6.0", prefix:"apache2.2-bin", reference:"2.2.16-6+squeeze15")) flag++;
if (deb_check(release:"6.0", prefix:"apache2.2-common", reference:"2.2.16-6+squeeze15")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
