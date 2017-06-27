#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2460. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58880);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/02/16 15:37:38 $");

  script_cve_id("CVE-2012-1183", "CVE-2012-2414", "CVE-2012-2415");
  script_bugtraq_id(52523, 53206, 53210);
  script_osvdb_id(80125, 81454, 81455);
  script_xref(name:"DSA", value:"2460");

  script_name(english:"Debian DSA-2460-1 : asterisk - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in the Asterisk PBX and
telephony toolkit :

  - CVE-2012-1183
    Russell Bryant discovered a buffer overflow in the
    Milliwatt application.

  - CVE-2012-2414
    David Woolley discovered a privilege escalation in the
    Asterisk manager interface.

  - CVE-2012-2415
    Russell Bryant discovered a buffer overflow in the
    Skinny driver."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-1183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-2414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-2415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/asterisk"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2460"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the asterisk packages.

For the stable distribution (squeeze), this problem has been fixed in
version 1:1.6.2.9-2+squeeze5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/26");
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
if (deb_check(release:"6.0", prefix:"asterisk", reference:"1:1.6.2.9-2+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-config", reference:"1:1.6.2.9-2+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-dbg", reference:"1:1.6.2.9-2+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-dev", reference:"1:1.6.2.9-2+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-doc", reference:"1:1.6.2.9-2+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-h323", reference:"1:1.6.2.9-2+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-sounds-main", reference:"1:1.6.2.9-2+squeeze5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
