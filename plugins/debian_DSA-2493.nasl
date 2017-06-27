#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2493. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59771);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2012-2947", "CVE-2012-2948");
  script_bugtraq_id(53722, 53723);
  script_osvdb_id(82450, 82451);
  script_xref(name:"DSA", value:"2493");

  script_name(english:"Debian DSA-2493-1 : asterisk - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Asterisk, a PBX and
telephony toolkit.

  - CVE-2012-2947
    The IAX2 channel driver allows remote attackers to cause
    a denial of service (daemon crash) by placing a call on
    hold (when a certain mohinterpret setting is enabled).

  - CVE-2012-2948
    The Skinny channel driver allows remote authenticated
    users to cause a denial of service (NULL pointer
    dereference and daemon crash) by closing a connection in
    off-hook mode.

In addition, it was discovered that Asterisk does not set the
alwaysauthreject option by default in the SIP channel driver. This
allows remote attackers to observe a difference in response behavior
and check for the presence of account names. (CVE-2011-2666 ) System
administrators concerned by this user enumerating vulnerability should
enable the alwaysauthreject option in the configuration. We do not
plan to change the default setting in the stable version (Asterisk
1.6) in order to preserve backwards compatibility."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=675204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=675210"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-2947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-2948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/asterisk"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2493"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the asterisk packages.

For the stable distribution (squeeze), this problem has been fixed in
version 1:1.6.2.9-2+squeeze6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/29");
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
if (deb_check(release:"6.0", prefix:"asterisk", reference:"1:1.6.2.9-2+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-config", reference:"1:1.6.2.9-2+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-dbg", reference:"1:1.6.2.9-2+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-dev", reference:"1:1.6.2.9-2+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-doc", reference:"1:1.6.2.9-2+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-h323", reference:"1:1.6.2.9-2+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-sounds-main", reference:"1:1.6.2.9-2+squeeze6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
