#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1702. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35365);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-5077", "CVE-2009-0021", "CVE-2009-0046", "CVE-2009-0047", "CVE-2009-0048", "CVE-2009-0049", "CVE-2009-0124", "CVE-2009-0125", "CVE-2009-0127", "CVE-2009-0128", "CVE-2009-0130");
  script_bugtraq_id(33150);
  script_osvdb_id(51164);
  script_xref(name:"DSA", value:"1702");

  script_name(english:"Debian DSA-1702-1 : ntp - interpretation conflict");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It has been discovered that NTP, an implementation of the Network Time
Protocol, does not properly check the result of an OpenSSL function
for verifying cryptographic signatures, which may ultimately lead to
the acceptance of unauthenticated time information. (Note that
cryptographic authentication of time servers is often not enabled in
the first place.)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=511227"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1702"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ntp package.

For the stable distribution (etch), this problem has been fixed in
version 4.2.2.p4+dfsg-2etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"ntp", reference:"4.2.2.p4+dfsg-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"ntp-doc", reference:"4.2.2.p4+dfsg-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"ntp-refclock", reference:"4.2.2.p4+dfsg-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"ntp-simple", reference:"4.2.2.p4+dfsg-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"ntpdate", reference:"4.2.2.p4+dfsg-2etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
