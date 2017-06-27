#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2761. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70002);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:43:09 $");

  script_cve_id("CVE-2013-4761", "CVE-2013-4956");
  script_bugtraq_id(61805, 61806);
  script_osvdb_id(96343, 96346);
  script_xref(name:"DSA", value:"2761");

  script_name(english:"Debian DSA-2761-1 : puppet - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in puppet, a centralized
configuration management system. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2013-4761
    The 'resource_type' service (disabled by default) could
    be used to make puppet load arbitrary Ruby code from
    puppet master's file system.

  - CVE-2013-4956
    Modules installed with the Puppet Module Tool might be
    installed with weak permissions, possibly allowing local
    users to read or modify them.

The stable distribution (wheezy) has been updated to version 2.7.33 of
puppet. This version includes the patches for all the previous DSAs
related to puppet in wheezy. In this version, the puppet report format
is now correctly reported as version 3.

It is to be expected that future DSAs for puppet update to a newer,
bug fix-only, release of the 2.7 branch.

The oldstable distribution (squeeze) has not been updated for this
advisory: as of this time there is no fix for CVE-2013-4761 and the
package is not affected by CVE-2013-4956."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4956"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4956"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/puppet"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2761"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the puppet packages.

For the stable distribution (wheezy), these problems have been fixed
in version 2.7.23-1~deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:puppet");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/20");
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
if (deb_check(release:"7.0", prefix:"puppet", reference:"2.7.23-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"puppet-common", reference:"2.7.23-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"puppet-el", reference:"2.7.23-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"puppet-testsuite", reference:"2.7.23-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"puppetmaster", reference:"2.7.23-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"puppetmaster-common", reference:"2.7.23-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"puppetmaster-passenger", reference:"2.7.23-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"vim-puppet", reference:"2.7.23-1~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
