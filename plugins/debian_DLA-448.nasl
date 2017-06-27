#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-448-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90805);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/12/06 20:03:51 $");

  script_cve_id("CVE-2016-2167", "CVE-2016-2168");
  script_osvdb_id(137779, 137780, 137803);

  script_name(english:"Debian DLA-448-1 : subversion security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2016-2167

svnserve, the svn:// protocol server, can optionally use the Cyrus
SASL library for authentication, integrity protection, and encryption.
Due to a programming oversight, authentication against Cyrus SASL
would permit the remote user to specify a realm string which is a
prefix of the expected realm string.

CVE-2016-2168

Subversion's httpd servers are vulnerable to a remotely triggerable
crash in the mod_authz_svn module. The crash can occur during an
authorization check for a COPY or MOVE request with a specially
crafted header value.

This allows remote attackers to cause a denial of service.

-- James GPG Key: 4096R/331BA3DB 2011-12-05 James McCoy
<jamessan@debian.org>

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/05/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/subversion"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/02");
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
if (deb_check(release:"7.0", prefix:"libapache2-svn", reference:"1.6.17dfsg-4+deb7u11")) flag++;
if (deb_check(release:"7.0", prefix:"libsvn-dev", reference:"1.6.17dfsg-4+deb7u11")) flag++;
if (deb_check(release:"7.0", prefix:"libsvn-doc", reference:"1.6.17dfsg-4+deb7u11")) flag++;
if (deb_check(release:"7.0", prefix:"libsvn-java", reference:"1.6.17dfsg-4+deb7u11")) flag++;
if (deb_check(release:"7.0", prefix:"libsvn-perl", reference:"1.6.17dfsg-4+deb7u11")) flag++;
if (deb_check(release:"7.0", prefix:"libsvn-ruby", reference:"1.6.17dfsg-4+deb7u11")) flag++;
if (deb_check(release:"7.0", prefix:"libsvn-ruby1.8", reference:"1.6.17dfsg-4+deb7u11")) flag++;
if (deb_check(release:"7.0", prefix:"libsvn1", reference:"1.6.17dfsg-4+deb7u11")) flag++;
if (deb_check(release:"7.0", prefix:"python-subversion", reference:"1.6.17dfsg-4+deb7u11")) flag++;
if (deb_check(release:"7.0", prefix:"subversion", reference:"1.6.17dfsg-4+deb7u11")) flag++;
if (deb_check(release:"7.0", prefix:"subversion-tools", reference:"1.6.17dfsg-4+deb7u11")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
