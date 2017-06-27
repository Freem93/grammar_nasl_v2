#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2274. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55537);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:31:55 $");

  script_cve_id("CVE-2011-1590", "CVE-2011-1957", "CVE-2011-1958", "CVE-2011-1959", "CVE-2011-2174", "CVE-2011-2175");
  script_bugtraq_id(47392, 48066);
  script_osvdb_id(71846, 72975, 72976, 72977, 72978, 72979);
  script_xref(name:"DSA", value:"2274");

  script_name(english:"Debian DSA-2274-1 : wireshark - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Huzaifa Sidhpurwala, David Maciejak and others discovered several
vulnerabilities in the X.509if and DICOM dissectors and in the code to
process various capture and dictionary files, which could lead to
denial of service or the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/wireshark"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2274"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wireshark packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.0.2-3+lenny14.

For the stable distribution (squeeze), this problem has been fixed in
version 1.2.11-6+squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"wireshark", reference:"1.0.2-3+lenny14")) flag++;
if (deb_check(release:"6.0", prefix:"tshark", reference:"1.2.11-6+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"wireshark", reference:"1.2.11-6+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"wireshark-common", reference:"1.2.11-6+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"wireshark-dbg", reference:"1.2.11-6+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"wireshark-dev", reference:"1.2.11-6+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
