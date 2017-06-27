#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2854. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72354);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/16 15:43:10 $");

  script_cve_id("CVE-2014-0044", "CVE-2014-0045");
  script_osvdb_id(102904, 102905);
  script_xref(name:"DSA", value:"2854");

  script_name(english:"Debian DSA-2854-1 : mumble - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several issues have been discovered in mumble, a low latency VoIP
client. The Common Vulnerabilities and Exposures project identifies
the following issues :

  - CVE-2014-0044
    It was discovered that a malformed Opus voice packet
    sent to a Mumble client could trigger a NULL pointer
    dereference or an out-of-bounds array access. A
    malicious remote attacker could exploit this flaw to
    mount a denial of service attack against a mumble client
    by causing the application to crash.

  - CVE-2014-0045
    It was discovered that a malformed Opus voice packet
    sent to a Mumble client could trigger a heap-based
    buffer overflow. A malicious remote attacker could use
    this flaw to cause a client crash (denial of service) or
    potentially use it to execute arbitrary code.

The oldstable distribution (squeeze) is not affected by these
problems."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=737739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0044"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0045"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/mumble"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2854"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mumble packages.

For the stable distribution (wheezy), these problems have been fixed
in version 1.2.3-349-g315b5f5-2.2+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mumble");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"mumble", reference:"1.2.3-349-g315b5f5-2.2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mumble-dbg", reference:"1.2.3-349-g315b5f5-2.2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mumble-server", reference:"1.2.3-349-g315b5f5-2.2+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
