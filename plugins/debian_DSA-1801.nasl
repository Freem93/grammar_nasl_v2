#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1801. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38833);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/11/14 12:03:06 $");

  script_cve_id("CVE-2009-0159", "CVE-2009-1252");
  script_bugtraq_id(34481, 35017);
  script_xref(name:"CERT", value:"853097");
  script_xref(name:"DSA", value:"1801");

  script_name(english:"Debian DSA-1801-1 : ntp - buffer overflows");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in NTP, the
Network Time Protocol reference implementation. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2009-0159
    A buffer overflow in ntpq allow a remote NTP server to
    create a denial of service attack or to execute
    arbitrary code via a crafted response.

  - CVE-2009-1252
    A buffer overflow in ntpd allows a remote attacker to
    create a denial of service attack or to execute
    arbitrary code when the autokey functionality is
    enabled."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=525373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1801"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ntp package.

For the old stable distribution (etch), these problems have been fixed
in version 4.2.2.p4+dfsg-2etch3.

For the stable distribution (lenny), these problems have been fixed in
version 4.2.4p4+dfsg-8lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"ntp", reference:"4.2.2.p4+dfsg-2etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ntp-doc", reference:"4.2.2.p4+dfsg-2etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ntp-refclock", reference:"4.2.2.p4+dfsg-2etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ntp-simple", reference:"4.2.2.p4+dfsg-2etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ntpdate", reference:"4.2.2.p4+dfsg-2etch3")) flag++;
if (deb_check(release:"5.0", prefix:"ntp", reference:"4.2.4p4+dfsg-8lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"ntp-doc", reference:"4.2.4p4+dfsg-8lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"ntpdate", reference:"4.2.4p4+dfsg-8lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
