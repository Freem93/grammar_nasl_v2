#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2622. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64624);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2013-0169", "CVE-2013-1621");
  script_bugtraq_id(57776, 57778, 57781);
  script_osvdb_id(89848, 89849, 90069);
  script_xref(name:"DSA", value:"2622");

  script_name(english:"Debian DSA-2622-1 : polarssl - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been found in PolarSSL. The Common
Vulnerabilities and Exposures project identifies the following issues
:

  - CVE-2013-0169
    A timing side channel attack has been found in CBC
    padding allowing an attacker to recover pieces of
    plaintext via statistical analysis of crafted packages,
    known as the 'Lucky Thirteen' issue.

  - CVE-2013-1621
    An array index error might allow remote attackers to
    cause a denial of service via vectors involving a
    crafted padding-length value during validation of CBC
    padding in a TLS session.

  - CVE-2013-1622
    Malformed CBC data in a TLS session could allow remote
    attackers to conduct distinguishing attacks via
    statistical analysis of timing side-channel data for
    crafted packets."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=699887"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-0169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1622"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/polarssl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2622"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the polarssl packages.

For the stable distribution (squeeze), these problems have been fixed
in version 0.12.1-1squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:polarssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/14");
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
if (deb_check(release:"6.0", prefix:"libpolarssl-dev", reference:"0.12.1-1squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libpolarssl-runtime", reference:"0.12.1-1squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libpolarssl0", reference:"0.12.1-1squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
