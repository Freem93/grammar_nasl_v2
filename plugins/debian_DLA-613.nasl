#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-613-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93385);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/06 20:03:52 $");

  script_cve_id("CVE-2014-9587", "CVE-2015-1433", "CVE-2016-4069");
  script_bugtraq_id(71909, 72401);
  script_osvdb_id(117870, 137777);

  script_name(english:"Debian DLA-613-1 : roundcube security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple CSRF and XSS issues allow remote attackers to hijack the
authentication and execute roundcube operations without the consent of
the user. In some cases, this could result in data loss or data theft.

CVE-2014-9587

Multiple cross-site request forgery (CSRF) vulnerabilities in allow
remote attackers to hijack the authentication of unspecified victims
via unknown vectors, related to (1) address book operations or the (2)
ACL or (3) Managesieve plugins.

CVE-2015-1433

Incorrect quotation logic during sanitization of style HTML attribute
allows remote attackers to execute arbitrary JavaScript code on the
user's browser. CVE-2016-4069

Cross-site request forgery (CSRF) vulnerability allows
remote attackers to hijack the authentication of users for
requests that download attachments and cause a denial of
service (disk consumption) via unspecified vectors.

For Debian 7 'Wheezy', these problems have been fixed in version
0.7.2-9+deb7u4.

We recommend that you upgrade your roundcube packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/09/msg00006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/roundcube"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:roundcube");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:roundcube-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:roundcube-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:roundcube-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:roundcube-plugins");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/09");
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
if (deb_check(release:"7.0", prefix:"roundcube", reference:"0.7.2-9+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"roundcube-core", reference:"0.7.2-9+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"roundcube-mysql", reference:"0.7.2-9+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"roundcube-pgsql", reference:"0.7.2-9+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"roundcube-plugins", reference:"0.7.2-9+deb7u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
