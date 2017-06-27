#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1525. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31631);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-6430", "CVE-2008-1332", "CVE-2008-1333");
  script_osvdb_id(43414);
  script_xref(name:"DSA", value:"1525");

  script_name(english:"Debian DSA-1525-1 : asterisk - several vulnerabilities");
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

  - CVE-2007-6430
    Tilghman Lesher discovered that database-based
    registrations are insufficiently validated. This only
    affects setups, which are configured to run without a
    password and only host-based authentication.

  - CVE-2008-1332
    Jason Parker discovered that insufficient validation of
    From: headers inside the SIP channel driver may lead to
    authentication bypass and the potential external
    initiation of calls.

  - CVE-2008-1333
    This update also fixes a format string vulnerability,
    which can only be triggered through configuration files
    under control of the local administrator. In later
    releases of Asterisk this issue is remotely exploitable
    and tracked as CVE-2008-1333.

The status of the old stable distribution (sarge) is currently being
investigated. If affected, an update will be released through
security.debian.org."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-6430"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1525"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the asterisk packages.

For the stable distribution (etch), these problems have been fixed in
version 1:1.2.13~dfsg-2etch3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(134, 264, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"asterisk", reference:"1:1.2.13~dfsg-2etch3")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-bristuff", reference:"1:1.2.13~dfsg-2etch3")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-classic", reference:"1:1.2.13~dfsg-2etch3")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-config", reference:"1:1.2.13~dfsg-2etch3")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-dev", reference:"1:1.2.13~dfsg-2etch3")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-doc", reference:"1:1.2.13~dfsg-2etch3")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-h323", reference:"1:1.2.13~dfsg-2etch3")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-sounds-main", reference:"1:1.2.13~dfsg-2etch3")) flag++;
if (deb_check(release:"4.0", prefix:"asterisk-web-vmail", reference:"1:1.2.13~dfsg-2etch3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
