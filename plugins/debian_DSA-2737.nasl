#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2737. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69354);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/16 15:43:09 $");

  script_cve_id("CVE-2013-2161", "CVE-2013-4155");
  script_bugtraq_id(60543, 61690);
  script_xref(name:"DSA", value:"2737");

  script_name(english:"Debian DSA-2737-1 : swift - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Swift, the Openstack
object storage. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2013-2161
    Alex Gaynor from Rackspace reported a vulnerability in
    XML handling within Swift account servers. Account
    strings were unescaped in xml listings, and an attacker
    could potentially generate unparsable or arbitrary XML
    responses which may be used to leverage other
    vulnerabilities in the calling software.

  - CVE-2013-4155
    Peter Portante from Red Hat reported a vulnerability in
    Swift. By issuing requests with an old X-Timestamp
    value, an authenticated attacker can fill an object
    server with superfluous object tombstones, which may
    significantly slow down subsequent requests to that
    object server, facilitating a Denial of Service attack
    against Swift clusters."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/swift"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2737"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the swift packages.

For the stable distribution (wheezy), these problems have been fixed
in version 1.4.8-2+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:swift");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/15");
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
if (deb_check(release:"7.0", prefix:"python-swift", reference:"1.4.8-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"swift", reference:"1.4.8-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"swift-account", reference:"1.4.8-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"swift-container", reference:"1.4.8-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"swift-doc", reference:"1.4.8-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"swift-object", reference:"1.4.8-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"swift-proxy", reference:"1.4.8-2+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
