#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2370. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57510);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:31:56 $");

  script_cve_id("CVE-2011-4528", "CVE-2011-4869");
  script_bugtraq_id(51115);
  script_osvdb_id(77909, 77910);
  script_xref(name:"DSA", value:"2370");

  script_name(english:"Debian DSA-2370-1 : unbound - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Unbound, a recursive DNS resolver, would crash
when processing certain malformed DNS responses from authoritative DNS
servers, leading to denial of service.

  - CVE-2011-4528
    Unbound attempts to free unallocated memory during
    processing of duplicate CNAME records in a signed zone.

  - CVE-2011-4869
    Unbound does not properly process malformed responses
    which lack expected NSEC3 records."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4869"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/unbound"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2370"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the unbound packages.

For the oldstable distribution (lenny), these problems have been fixed
in version 1.4.6-1~lenny2.

For the stable distribution (squeeze), these problems have been fixed
in version 1.4.6-1+squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:unbound");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"unbound", reference:"1.4.6-1~lenny2")) flag++;
if (deb_check(release:"6.0", prefix:"libunbound-dev", reference:"1.4.6-1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libunbound2", reference:"1.4.6-1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"unbound", reference:"1.4.6-1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"unbound-host", reference:"1.4.6-1+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
