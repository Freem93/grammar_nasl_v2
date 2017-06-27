#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1673. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34974);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-3137", "CVE-2008-3138", "CVE-2008-3141", "CVE-2008-3145", "CVE-2008-3933", "CVE-2008-4683", "CVE-2008-4684", "CVE-2008-4685");
  script_bugtraq_id(30020, 30181, 31009, 31838);
  script_osvdb_id(46646, 46647, 46648, 49343, 49344);
  script_xref(name:"DSA", value:"1673");

  script_name(english:"Debian DSA-1673-1 : wireshark - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in network traffic
analyzer Wireshark. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2008-3137
    The GSM SMS dissector is vulnerable to denial of
    service.

  - CVE-2008-3138
    The PANA and KISMET dissectors are vulnerable to denial
    of service.

  - CVE-2008-3141
    The RMI dissector could disclose system memory.

  - CVE-2008-3145
    The packet reassembling module is vulnerable to denial
    of service.

  - CVE-2008-3933
    The zlib uncompression module is vulnerable to denial of
    service.

  - CVE-2008-4683
    The Bluetooth ACL dissector is vulnerable to denial of
    service.

  - CVE-2008-4684
    The PRP and MATE dissectors are vulnerable to denial of
    service.

  - CVE-2008-4685
    The Q931 dissector is vulnerable to denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3137"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3933"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4683"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1673"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wireshark packages.

For the stable distribution (etch), these problems have been fixed in
version 0.99.4-5.etch.3.

For the upcoming stable distribution (lenny), these problems have been
fixed in version 1.0.2-3+lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/01");
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
if (deb_check(release:"4.0", prefix:"ethereal", reference:"0.99.4-5.etch.3")) flag++;
if (deb_check(release:"4.0", prefix:"ethereal-common", reference:"0.99.4-5.etch.3")) flag++;
if (deb_check(release:"4.0", prefix:"ethereal-dev", reference:"0.99.4-5.etch.3")) flag++;
if (deb_check(release:"4.0", prefix:"tethereal", reference:"0.99.4-5.etch.3")) flag++;
if (deb_check(release:"4.0", prefix:"tshark", reference:"0.99.4-5.etch.3")) flag++;
if (deb_check(release:"4.0", prefix:"wireshark", reference:"0.99.4-5.etch.3")) flag++;
if (deb_check(release:"4.0", prefix:"wireshark-common", reference:"0.99.4-5.etch.3")) flag++;
if (deb_check(release:"4.0", prefix:"wireshark-dev", reference:"0.99.4-5.etch.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
