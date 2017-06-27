#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3309. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84837);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/05/26 15:53:38 $");

  script_cve_id("CVE-2015-5522", "CVE-2015-5523");
  script_bugtraq_id(75037);
  script_xref(name:"DSA", value:"3309");

  script_name(english:"Debian DSA-3309-1 : tidy - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fernando Munoz discovered that invalid HTML input passed to tidy, an
HTML syntax checker and reformatter, could trigger a buffer overflow.
This could allow remote attackers to cause a denial of service (crash)
or potentially execute arbitrary code.

Geoff McLane also discovered that a similar issue could trigger an
integer overflow, leading to a memory allocation of 4GB. This could
allow remote attackers to cause a denial of service by saturating the
target's memory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=792571"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/tidy"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/tidy"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3309"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the tidy packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 20091223cvs-1.2+deb7u1.

For the stable distribution (jessie), these problems have been fixed
in version 20091223cvs-1.4+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tidy");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libtidy-0.99-0", reference:"20091223cvs-1.2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libtidy-dev", reference:"20091223cvs-1.2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"tidy", reference:"20091223cvs-1.2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"tidy-doc", reference:"20091223cvs-1.2+deb7u1")) flag++;
if (deb_check(release:"8.0", prefix:"libtidy-0.99-0", reference:"20091223cvs-1.4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libtidy-dev", reference:"20091223cvs-1.4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"tidy", reference:"20091223cvs-1.4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"tidy-doc", reference:"20091223cvs-1.4+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
