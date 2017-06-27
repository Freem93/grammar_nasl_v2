#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1358. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25938);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/08/06 14:06:07 $");

  script_cve_id("CVE-2007-1306", "CVE-2007-1561", "CVE-2007-2294", "CVE-2007-2297", "CVE-2007-2488", "CVE-2007-3762", "CVE-2007-3763", "CVE-2007-3764");
  script_osvdb_id(38194, 38195, 38196);
  script_xref(name:"DSA", value:"1358");

  script_name(english:"Debian DSA-1358-1 : asterisk - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in Asterisk, a
free software PBX and telephony toolkit. The Common Vulnerabilities
and Exposures project identifies the following problems :

  - CVE-2007-1306
    'Mu Security' discovered that a NULL pointer dereference
    in the SIP implementation could lead to denial of
    service.

  - CVE-2007-1561
    Inria Lorraine discovered that a programming error in
    the SIP implementation could lead to denial of service.

  - CVE-2007-2294
    It was discovered that a NULL pointer dereference in the
    manager interface could lead to denial of service.

  - CVE-2007-2297
    It was discovered that a programming error in the SIP
    implementation could lead to denial of service.

  - CVE-2007-2488
    Tim Panton and Birgit Arkestein discovered that a
    programming error in the IAX2 implementation could lead
    to information disclosure.

  - CVE-2007-3762
    Russell Bryant discovered that a buffer overflow in the
    IAX implementation could lead to the execution of
    arbitrary code.

  - CVE-2007-3763
    Chris Clark and Zane Lackey discovered that several NULL
    pointer dereferences in the IAX2 implementation could
    lead to denial of service.

  - CVE-2007-3764
    Will Drewry discovered that a programming error in the
    Skinny implementation could lead to denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1306"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2294"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2297"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3763"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3764"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1358"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Asterisk packages.

For the oldstable distribution (sarge) these problems have been fixed
in version 1.0.7.dfsg.1-2sarge5.

For the stable distribution (etch) these problems have been fixed in
version 1:1.2.13~dfsg-2etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/28");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"asterisk", reference:"1.0.7.dfsg.1-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"asterisk-config", reference:"1.0.7.dfsg.1-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"asterisk-dev", reference:"1.0.7.dfsg.1-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"asterisk-doc", reference:"1.0.7.dfsg.1-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"asterisk-gtk-console", reference:"1.0.7.dfsg.1-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"asterisk-h323", reference:"1.0.7.dfsg.1-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"asterisk-sounds-main", reference:"1.0.7.dfsg.1-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"asterisk-web-vmail", reference:"1.0.7.dfsg.1-2sarge5")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk", reference:"1:1.2.13~dfsg-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-bristuff", reference:"1:1.2.13~dfsg-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-classic", reference:"1:1.2.13~dfsg-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-config", reference:"1:1.2.13~dfsg-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-dev", reference:"1:1.2.13~dfsg-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-doc", reference:"1:1.2.13~dfsg-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-h323", reference:"1:1.2.13~dfsg-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-sounds-main", reference:"1:1.2.13~dfsg-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-web-vmail", reference:"1:1.2.13~dfsg-2etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
