#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2367. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57507);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2011-4597", "CVE-2011-4598");
  script_bugtraq_id(50989, 50990);
  script_osvdb_id(77597, 77598);
  script_xref(name:"DSA", value:"2367");

  script_name(english:"Debian DSA-2367-1 : asterisk - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Asterisk, an Open
Source PBX and telephony toolkit :

  - CVE-2011-4597
    Ben Williams discovered that it was possible to
    enumerate SIP user names in some configurations. Please
    see the upstream advisory for details.

  This update only modifies the sample sip.conf configuration file.
  Please see README.Debian for more information on how to update your
  installation.

  - CVE-2011-4598
    Kristijan Vrban discovered that Asterisk can be crashed
    with malformed SIP packets if the 'automon' feature is
    enabled."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4597"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2011-013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/asterisk"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2367"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the asterisk packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 1:1.4.21.2~dfsg-3+lenny6.

For the stable distribution (squeeze), this problem has been fixed in
version 1:1.6.2.9-2+squeeze4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/12");
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
if (deb_check(release:"5.0", prefix:"asterisk", reference:"1:1.4.21.2~dfsg-3+lenny6")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk", reference:"1:1.6.2.9-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-config", reference:"1:1.6.2.9-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-dbg", reference:"1:1.6.2.9-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-dev", reference:"1:1.6.2.9-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-doc", reference:"1:1.6.2.9-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-h323", reference:"1:1.6.2.9-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"asterisk-sounds-main", reference:"1:1.6.2.9-2+squeeze4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
