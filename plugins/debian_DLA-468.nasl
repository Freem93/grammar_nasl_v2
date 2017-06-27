#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-468-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91108);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/06/27 14:13:07 $");

  script_cve_id("CVE-2015-3245", "CVE-2015-3246");
  script_bugtraq_id(76021, 76022);
  script_osvdb_id(125263, 125264);
  script_xref(name:"IAVA", value:"2015-A-0179");

  script_name(english:"Debian DLA-468-1 : libuser security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two security vulnerabilities were discovered in libuser, a library
that implements a standardized interface for manipulating and
administering user and group accounts, that could lead to a denial of
service or privilege escalation by local users.

CVE-2015-3245 Incomplete blacklist vulnerability in the chfn function
in libuser before 0.56.13-8 and 0.60 before 0.60-7, as used in the
userhelper program in the usermode package, allows local users to
cause a denial of service (/etc/passwd corruption) via a newline
character in the GECOS field.

CVE-2015-3246 libuser before 0.56.13-8 and 0.60 before 0.60-7, as used
in the userhelper program in the usermode package, directly modifies
/etc/passwd, which allows local users to cause a denial of service
(inconsistent file state) by causing an error during the modification.
NOTE: this issue can be combined with CVE-2015-3245 to gain
privileges.

In addition the usermode package, which depends on libuser, was
rebuilt against the updated version.

For Debian 7 'Wheezy', these problems have been fixed in

libuser 1:0.56.9.dfsg.1-1.2+deb7u1 usermode 1.109-1+deb7u2

We recommend that you upgrade your libuser and usermode packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/05/msg00021.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libuser"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libuser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libuser1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libuser1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-libuser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/13");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libuser", reference:"1:0.56.9.dfsg.1-1.2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libuser1", reference:"1:0.56.9.dfsg.1-1.2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libuser1-dev", reference:"1:0.56.9.dfsg.1-1.2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python-libuser", reference:"1:0.56.9.dfsg.1-1.2+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
