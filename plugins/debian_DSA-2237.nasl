#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2237. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53900);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2011-0419");
  script_bugtraq_id(47820, 47929);
  script_osvdb_id(73388);
  script_xref(name:"DSA", value:"2237");

  script_name(english:"Debian DSA-2237-1 : apr - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was found in the APR library, which could be exploited through
Apache HTTPD's mod_autoindex. If a directory indexed by mod_autoindex
contained files with sufficiently long names, a remote attacker could
send a carefully crafted request which would cause excessive CPU
usage. This could be used in a denial of service attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/apr"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2237"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the apr packages and restart the apache2 server.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.2.12-5+lenny3.

For the stable distribution (squeeze), this problem has been fixed in
version 1.4.2-6+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"apr", reference:"1.2.12-5+lenny3")) flag++;
if (deb_check(release:"6.0", prefix:"libapr1", reference:"1.4.2-6+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libapr1-dbg", reference:"1.4.2-6+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libapr1-dev", reference:"1.4.2-6+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
