#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2511. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60002);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2012-3864", "CVE-2012-3865", "CVE-2012-3866", "CVE-2012-3867");
  script_bugtraq_id(54399);
  script_xref(name:"DSA", value:"2511");

  script_name(english:"Debian DSA-2511-1 : puppet - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security vulnerabilities have been found in Puppet, a
centralized configuration management :

  - CVE-2012-3864
    Authenticated clients could read arbitrary files on the
    puppet master.

  - CVE-2012-3865
    Authenticated clients could delete arbitrary files on
    the puppet master.

  - CVE-2012-3866
    The report of the most recent Puppet run was stored with
    world readable permissions, resulting in information
    disclosure.

  - CVE-2012-3867
    Agent hostnames were insufficiently validated."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3865"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3866"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/puppet"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2511"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the puppet packages.

For the stable distribution (squeeze), this problem has been fixed in
version 2.6.2-5+squeeze6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:puppet");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"puppet", reference:"2.6.2-5+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"puppet-common", reference:"2.6.2-5+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"puppet-el", reference:"2.6.2-5+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"puppet-testsuite", reference:"2.6.2-5+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"puppetmaster", reference:"2.6.2-5+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"vim-puppet", reference:"2.6.2-5+squeeze6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
