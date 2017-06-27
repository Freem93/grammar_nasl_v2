#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1135. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22677);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/17 23:36:52 $");

  script_cve_id("CVE-2006-3600");
  script_bugtraq_id(18961);
  script_osvdb_id(27094);
  script_xref(name:"DSA", value:"1135");

  script_name(english:"Debian DSA-1135-1 : libtunepimp - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Kevin Kofler discovered several stack-based buffer overflows in the
LookupTRM::lookup function in libtunepimp, a MusicBrainz tagging
library, which allows remote attackers to cause a denial of service or
execute arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=378091"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1135"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libtunepimp packages.

For the stable distribution (sarge) these problems have been fixed in
version 0.3.0-3sarge2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtunepimp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libtunepimp-bin", reference:"0.3.0-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libtunepimp-perl", reference:"0.3.0-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libtunepimp2", reference:"0.3.0-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libtunepimp2-dev", reference:"0.3.0-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"python-tunepimp", reference:"0.3.0-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"python2.2-tunepimp", reference:"0.3.0-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"python2.3-tunepimp", reference:"0.3.0-3sarge2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
