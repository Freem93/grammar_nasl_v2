#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3154. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81189);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/23 13:44:41 $");

  script_cve_id("CVE-2014-9750", "CVE-2014-9751");
  script_osvdb_id(116071, 116072);
  script_xref(name:"DSA", value:"3154");
  script_xref(name:"TRA", value:"TRA-2015-04");

  script_name(english:"Debian DSA-3154-1 : ntp - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in the ntp package, an
implementation of the Network Time Protocol. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2014-9750
    Stephen Roettger of the Google Security Team, Sebastian
    Krahmer of the SUSE Security Team and Harlan Stenn of
    Network Time Foundation discovered that the length value
    in extension fields is not properly validated in several
    code paths in ntp_crypto.c, which could lead to
    information leakage or denial of service (ntpd crash).

  - CVE-2014-9751
    Stephen Roettger of the Google Security Team reported
    that ACLs based on IPv6 ::1 addresses can be bypassed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9750"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9751"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/ntp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2015-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ntp packages.

For the stable distribution (wheezy), these problems have been fixed
in version 1:4.2.6.p5+dfsg-2+deb7u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"ntp", reference:"1:4.2.6.p5+dfsg-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"ntp-doc", reference:"1:4.2.6.p5+dfsg-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"ntpdate", reference:"1:4.2.6.p5+dfsg-2+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
