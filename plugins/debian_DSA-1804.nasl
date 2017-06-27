#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1804. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38861);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/05 14:49:56 $");

  script_cve_id("CVE-2009-1574", "CVE-2009-1632");
  script_bugtraq_id(34765);
  script_osvdb_id(54286, 56400, 56401);
  script_xref(name:"DSA", value:"1804");

  script_name(english:"Debian DSA-1804-1 : ipsec-tools - NULL pointer dereference, memory leaks");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in racoon, the
Internet Key Exchange daemon of ipsec-tools. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2009-1574
    Neil Kettle discovered a NULL pointer dereference on
    crafted fragmented packets that contain no payload. This
    results in the daemon crashing which can be used for
    denial of service attacks.

  - CVE-2009-1632
    Various memory leaks in the X.509 certificate
    authentication handling and the NAT-Traversal keepalive
    implementation can result in memory exhaustion and thus
    denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=527634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=528933"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1574"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1804"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ipsec-tools packages.

For the oldstable distribution (etch), this problem has been fixed in
version 0.6.6-3.1etch3.

For the stable distribution (lenny), this problem has been fixed in
version 0.7.1-1.3+lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ipsec-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/22");
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
if (deb_check(release:"4.0", prefix:"ipsec-tools", reference:"0.6.6-3.1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"racoon", reference:"0.6.6-3.1etch3")) flag++;
if (deb_check(release:"5.0", prefix:"ipsec-tools", reference:"0.7.1-1.3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"racoon", reference:"0.7.1-1.3+lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
