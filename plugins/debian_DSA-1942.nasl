#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1942. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44807);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2008-1829", "CVE-2009-1268", "CVE-2009-1829", "CVE-2009-2560", "CVE-2009-2562", "CVE-2009-3241", "CVE-2009-3550", "CVE-2009-3829");
  script_bugtraq_id(34457, 35748, 36408, 36591, 36846);
  script_osvdb_id(53670, 54629, 56017, 56019, 56020, 56021, 58157, 59460, 59461, 59478);
  script_xref(name:"DSA", value:"1942");

  script_name(english:"Debian DSA-1942-1 : wireshark - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in the Wireshark
network traffic analyzer, which may lead to the execution of arbitrary
code or denial of service. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2009-2560
    A NULL pointer dereference was found in the RADIUS
    dissector.

  - CVE-2009-3550
    A NULL pointer dereference was found in the DCERP/NT
    dissector.

  - CVE-2009-3829
    An integer overflow was discovered in the ERF parser.

This update also includes fixes for three minor issues (CVE-2008-1829,
CVE-2009-2562, CVE-2009-3241 ), which were scheduled for the next
stable point update. Also CVE-2009-1268 was fixed for Etch. Since this
security update was issued prior to the release of the point update,
the fixes were included."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2560"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2562"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1268"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1942"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Wireshark packages.

For the old stable distribution (etch), this problem has been fixed in
version 0.99.4-5.etch.4.

For the stable distribution (lenny), this problem has been fixed in
version 1.0.2-3+lenny7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"ethereal", reference:"0.99.4-5.etch.4")) flag++;
if (deb_check(release:"4.0", prefix:"ethereal-common", reference:"0.99.4-5.etch.4")) flag++;
if (deb_check(release:"4.0", prefix:"ethereal-dev", reference:"0.99.4-5.etch.4")) flag++;
if (deb_check(release:"4.0", prefix:"tethereal", reference:"0.99.4-5.etch.4")) flag++;
if (deb_check(release:"4.0", prefix:"tshark", reference:"0.99.4-5.etch.4")) flag++;
if (deb_check(release:"4.0", prefix:"wireshark", reference:"0.99.4-5.etch.4")) flag++;
if (deb_check(release:"4.0", prefix:"wireshark-common", reference:"0.99.4-5.etch.4")) flag++;
if (deb_check(release:"4.0", prefix:"wireshark-dev", reference:"0.99.4-5.etch.4")) flag++;
if (deb_check(release:"5.0", prefix:"tshark", reference:"1.0.2-3+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"wireshark", reference:"1.0.2-3+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"wireshark-common", reference:"1.0.2-3+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"wireshark-dev", reference:"1.0.2-3+lenny7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
