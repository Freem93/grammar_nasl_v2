#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3846. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100070);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/12 13:30:58 $");

  script_cve_id("CVE-2017-6298", "CVE-2017-6299", "CVE-2017-6300", "CVE-2017-6301", "CVE-2017-6302", "CVE-2017-6303", "CVE-2017-6304", "CVE-2017-6305", "CVE-2017-6306", "CVE-2017-6800", "CVE-2017-6801", "CVE-2017-6802");
  script_osvdb_id(152488, 152489, 152490, 152491, 152492, 152493, 152494, 152495, 152496, 152497, 152513, 153356, 153357, 153358);
  script_xref(name:"DSA", value:"3846");

  script_name(english:"Debian DSA-3846-1 : libytnef - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several issues were discovered in libytnef, a library used to decode
application/ms-tnef e-mail attachments. Multiple heap overflows,
out-of-bound writes and reads, NULL pointer dereferences and infinite
loops could be exploited by tricking a user into opening a maliciously
crafted winmail.dat file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libytnef"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2017/dsa-3846"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libytnef packages.

For the stable distribution (jessie), these problems have been fixed
in version 1.5-6+deb8u1.

For the upcoming stable (stretch) and unstable (sid) distributions,
these problems have been fixed in version 1.9.2-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libytnef");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"libytnef0", reference:"1.5-6+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libytnef0-dev", reference:"1.5-6+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
