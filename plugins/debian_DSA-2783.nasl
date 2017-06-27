#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2783. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70534);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/16 15:43:10 $");

  script_cve_id("CVE-2011-5036", "CVE-2013-0183", "CVE-2013-0184", "CVE-2013-0263");
  script_bugtraq_id(51197, 57860, 58769);
  script_osvdb_id(78121, 89327, 89939);
  script_xref(name:"DSA", value:"2783");

  script_name(english:"Debian DSA-2783-1 : librack-ruby - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Rack, a modular Ruby
webserver interface. The Common Vulnerabilites and Exposures project
identifies the following vulnerabilities :

  - CVE-2011-5036
    Rack computes hash values for form parameters without
    restricting the ability to trigger hash collisions
    predictably, which allows remote attackers to cause a
    denial of service (CPU consumption) by sending many
    crafted parameters.

  - CVE-2013-0183
    A remote attacker could cause a denial of service
    (memory consumption and out-of-memory error) via a long
    string in a Multipart HTTP packet.

  - CVE-2013-0184
    A vulnerability in Rack::Auth::AbstractRequest allows
    remote attackers to cause a denial of service via
    unknown vectors.

  - CVE-2013-0263
    Rack::Session::Cookie allows remote attackers to guess
    the session cookie, gain privileges, and execute
    arbitrary code via a timing attack involving an HMAC
    comparison function that does not run in constant time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=653963"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=698440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=700226"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-5036"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-0183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-0184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-0263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/librack-ruby"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2783"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the librack-ruby packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 1.1.0-4+squeeze1.

The stable, testing and unstable distributions do not contain the
librack-ruby package. They have already been addressed in version
1.4.1-2.1 of the ruby-rack package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librack-ruby");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/22");
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
if (deb_check(release:"6.0", prefix:"librack-ruby", reference:"1.1.0-4+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"librack-ruby1.8", reference:"1.1.0-4+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"librack-ruby1.9.1", reference:"1.1.0-4+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
