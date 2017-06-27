#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-270-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84676);
  script_version("$Revision: 2.11 $");
  script_cvs_date("$Date: 2016/05/05 14:49:54 $");

  script_cve_id("CVE-2015-4620");
  script_bugtraq_id(75588);
  script_osvdb_id(124233);

  script_name(english:"Debian DLA-270-1 : bind9 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability has been found in the Internet Domain Name Server
bind9 :

CVE-2015-4620

Breno Silveira Soares of Servico Federal de Processamento de Dados
(SERPRO) discovered that the BIND DNS server is prone to a denial of
service vulnerability. A remote attacker who can cause a validating
resolver to query a zone containing specifically constructed contents
can cause the resolver to terminate with an assertion failure,
resulting in a denial of service to clients relying on the resolver.

For the squeeze distribution, these issues have been fixed in version
9.7.3.dfsg-1~squeeze15 of bind9.

We recommend that you upgrade your bind9 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/07/msg00008.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/bind9"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dnsutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbind-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbind9-60");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdns69");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisc62");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisccc60");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisccfg62");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblwres60");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lwresd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/14");
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
if (deb_check(release:"6.0", prefix:"bind9", reference:"9.7.3.dfsg-1~squeeze15")) flag++;
if (deb_check(release:"6.0", prefix:"bind9-doc", reference:"9.7.3.dfsg-1~squeeze15")) flag++;
if (deb_check(release:"6.0", prefix:"bind9-host", reference:"9.7.3.dfsg-1~squeeze15")) flag++;
if (deb_check(release:"6.0", prefix:"bind9utils", reference:"9.7.3.dfsg-1~squeeze15")) flag++;
if (deb_check(release:"6.0", prefix:"dnsutils", reference:"9.7.3.dfsg-1~squeeze15")) flag++;
if (deb_check(release:"6.0", prefix:"host", reference:"9.7.3.dfsg-1~squeeze15")) flag++;
if (deb_check(release:"6.0", prefix:"libbind-dev", reference:"9.7.3.dfsg-1~squeeze15")) flag++;
if (deb_check(release:"6.0", prefix:"libbind9-60", reference:"9.7.3.dfsg-1~squeeze15")) flag++;
if (deb_check(release:"6.0", prefix:"libdns69", reference:"9.7.3.dfsg-1~squeeze15")) flag++;
if (deb_check(release:"6.0", prefix:"libisc62", reference:"9.7.3.dfsg-1~squeeze15")) flag++;
if (deb_check(release:"6.0", prefix:"libisccc60", reference:"9.7.3.dfsg-1~squeeze15")) flag++;
if (deb_check(release:"6.0", prefix:"libisccfg62", reference:"9.7.3.dfsg-1~squeeze15")) flag++;
if (deb_check(release:"6.0", prefix:"liblwres60", reference:"9.7.3.dfsg-1~squeeze15")) flag++;
if (deb_check(release:"6.0", prefix:"lwresd", reference:"9.7.3.dfsg-1~squeeze15")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
