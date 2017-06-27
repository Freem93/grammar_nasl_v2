#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1049. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(22591);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/05/05 14:49:55 $");

  script_cve_id("CVE-2006-1932", "CVE-2006-1933", "CVE-2006-1934", "CVE-2006-1935", "CVE-2006-1936", "CVE-2006-1937", "CVE-2006-1938", "CVE-2006-1939", "CVE-2006-1940");
  script_bugtraq_id(17682);
  script_osvdb_id(24906, 24907, 24908, 24909, 24910, 24911, 24912, 24913, 24914, 24915, 24916, 24917, 24918, 24919, 24920, 24921, 24922, 24923, 24924, 24925, 24926, 24927, 24928, 24929, 24930, 24931, 24932, 24933);
  script_xref(name:"DSA", value:"1049");

  script_name(english:"Debian DSA-1049-1 : ethereal - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Gerald Combs reported several vulnerabilities in ethereal, a popular
network traffic analyser. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2006-1932
    The OID printing routine is susceptible to an off-by-one
    error.

  - CVE-2006-1933
    The UMA and BER dissectors could go into an infinite
    loop.

  - CVE-2006-1934
    The Network Instruments file code could overrun a
    buffer.

  - CVE-2006-1935
    The COPS dissector contains a potential buffer overflow.

  - CVE-2006-1936
    The telnet dissector contains a buffer overflow.

  - CVE-2006-1937
    Bugs in the SRVLOC and AIM dissector, and in the
    statistics counter could crash ethereal.

  - CVE-2006-1938
    NULL pointer dereferences in the SMB PIPE dissector and
    when reading a malformed Sniffer capture could crash
    ethereal.

  - CVE-2006-1939
    NULL pointer dereferences in the ASN.1, GSM SMS, RPC and
    ASN.1-based dissector and an invalid display filter
    could crash ethereal.

  - CVE-2006-1940
    The SNDCP dissector could cause an unintended abortion."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1932"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1933"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1935"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1937"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1938"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1939"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1049"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ethereal packages.

For the old stable distribution (woody) these problems have been fixed
in version 0.9.4-1woody15.

For the stable distribution (sarge) these problems have been fixed in
version 0.10.10-2sarge5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ethereal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"ethereal", reference:"0.9.4-1woody15")) flag++;
if (deb_check(release:"3.0", prefix:"ethereal-common", reference:"0.9.4-1woody15")) flag++;
if (deb_check(release:"3.0", prefix:"ethereal-dev", reference:"0.9.4-1woody15")) flag++;
if (deb_check(release:"3.0", prefix:"tethereal", reference:"0.9.4-1woody15")) flag++;
if (deb_check(release:"3.1", prefix:"ethereal", reference:"0.10.10-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"ethereal-common", reference:"0.10.10-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"ethereal-dev", reference:"0.10.10-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"tethereal", reference:"0.10.10-2sarge5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
