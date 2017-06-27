#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2792. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70749);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/02/16 15:43:10 $");

  script_cve_id("CVE-2013-6336", "CVE-2013-6337", "CVE-2013-6338", "CVE-2013-6340");
  script_bugtraq_id(63500, 63502, 63503, 63504);
  script_osvdb_id(99262, 99275, 99276, 99278);
  script_xref(name:"DSA", value:"2792");

  script_name(english:"Debian DSA-2792-1 : wireshark - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in the dissectors for IEEE
802.15.4, NBAP, SIP and TCP, which could result in denial of service.

The oldstable distribution (squeeze) is only affected by
CVE-2013-6340. This problem has been fixed in version
1.2.11-6+squeeze13."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/wireshark"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2792"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wireshark packages.

For the stable distribution (wheezy), these problems have been fixed
in version 1.8.2-5wheezy7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libwireshark-data", reference:"1.8.2-5wheezy7")) flag++;
if (deb_check(release:"7.0", prefix:"libwireshark-dev", reference:"1.8.2-5wheezy7")) flag++;
if (deb_check(release:"7.0", prefix:"libwireshark2", reference:"1.8.2-5wheezy7")) flag++;
if (deb_check(release:"7.0", prefix:"libwiretap-dev", reference:"1.8.2-5wheezy7")) flag++;
if (deb_check(release:"7.0", prefix:"libwiretap2", reference:"1.8.2-5wheezy7")) flag++;
if (deb_check(release:"7.0", prefix:"libwsutil-dev", reference:"1.8.2-5wheezy7")) flag++;
if (deb_check(release:"7.0", prefix:"libwsutil2", reference:"1.8.2-5wheezy7")) flag++;
if (deb_check(release:"7.0", prefix:"tshark", reference:"1.8.2-5wheezy7")) flag++;
if (deb_check(release:"7.0", prefix:"wireshark", reference:"1.8.2-5wheezy7")) flag++;
if (deb_check(release:"7.0", prefix:"wireshark-common", reference:"1.8.2-5wheezy7")) flag++;
if (deb_check(release:"7.0", prefix:"wireshark-dbg", reference:"1.8.2-5wheezy7")) flag++;
if (deb_check(release:"7.0", prefix:"wireshark-dev", reference:"1.8.2-5wheezy7")) flag++;
if (deb_check(release:"7.0", prefix:"wireshark-doc", reference:"1.8.2-5wheezy7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
