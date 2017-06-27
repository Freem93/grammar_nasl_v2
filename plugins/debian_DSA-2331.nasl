#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2331. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56670);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:31:56 $");

  script_cve_id("CVE-2011-2768", "CVE-2011-2769");
  script_osvdb_id(76629, 76630);
  script_xref(name:"DSA", value:"2331");

  script_name(english:"Debian DSA-2331-1 : tor - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It has been discovered by 'frosty_un' that a design flaw in Tor, an
online privacy tool, allows malicious relay servers to learn certain
information that they should not be able to learn. Specifically, a
relay that a user connects to directly could learn which other relays
that user is connected to directly. In combination with other attacks,
this issue can lead to deanonymizing the user. The Common
Vulnerabilities and Exposures project has assigned CVE-2011-2768 to
this issue.

In addition to fixing the above mentioned issues, the updates to
oldstable and stable fix a number of less critical issues
(CVE-2011-2769 ). Please see the posting from the Tor blog for more
information."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2768"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blog.torproject.org/blog/tor-02234-released-security-patches"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/tor"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2331"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the tor packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 0.2.1.31-1~lenny+1. Due to technical limitations in the Debian
archive scripts, the update cannot be released synchronously with the
packages for stable. It will be released shortly.

For the stable distribution (squeeze), this problem has been fixed in
version 0.2.1.31-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/31");
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
if (deb_check(release:"5.0", prefix:"tor", reference:"0.2.1.31-1~lenny+1")) flag++;
if (deb_check(release:"6.0", prefix:"tor", reference:"0.2.1.31-1")) flag++;
if (deb_check(release:"6.0", prefix:"tor-dbg", reference:"0.2.1.31-1")) flag++;
if (deb_check(release:"6.0", prefix:"tor-geoipdb", reference:"0.2.1.31-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
