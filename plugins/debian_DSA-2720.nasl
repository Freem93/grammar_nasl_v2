#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2720. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67201);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/05 14:58:43 $");

  script_cve_id("CVE-2013-0795", "CVE-2013-0801", "CVE-2013-1670", "CVE-2013-1674", "CVE-2013-1675", "CVE-2013-1676", "CVE-2013-1677", "CVE-2013-1678", "CVE-2013-1679", "CVE-2013-1680", "CVE-2013-1681", "CVE-2013-1682", "CVE-2013-1684", "CVE-2013-1685", "CVE-2013-1686", "CVE-2013-1687", "CVE-2013-1690", "CVE-2013-1692", "CVE-2013-1693", "CVE-2013-1694", "CVE-2013-1697");
  script_bugtraq_id(60765, 60766, 60773, 60774, 60776, 60777, 60778, 60783, 60784, 60787);
  script_osvdb_id(94578, 94581, 94582, 94583, 94584, 94587, 94588, 94589, 94591, 94596);
  script_xref(name:"DSA", value:"2720");

  script_name(english:"Debian DSA-2720-1 : icedove - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues have been found in Icedove, Debian's version
of the Mozilla Thunderbird mail and news client. Multiple memory
safety errors, use-after-free vulnerabilities, missing permission
checks, incorrect memory handling and other implementation errors may
lead to the execution of arbitrary code, privilege escalation,
information disclosure or cross-site request forgery.

As already announced for Iceweasel: we're changing the approach for
security updates for Icedove in stable-security: instead of
backporting security fixes, we now provide releases based on the
Extended Support Release branch. As such, this update introduces
packages based on Thunderbird 17 and at some point in the future we
will switch to the next ESR branch once ESR 17 has reached it's end of
life.

Some Icedove extensions currently packaged in the Debian archive are
not compatible with the new browser engine. Up-to-date and compatible
versions can be retrieved from http://addons.mozilla.org as a short
term solution.

An updated and compatible version of Enigmail is included with this
update.

The Icedove version in the oldstable distribution (squeeze) is no
longer supported with full security updates. However, it should be
noted that almost all security issues in Icedove stem from the
included browser engine. These security problems only affect Icedove
if scripting and HTML mails are enabled. If there are security issues
specific to Icedove (e.g. a hypothetical buffer overflow in the IMAP
implementation) we'll make an effort to backport such fixes to
oldstable."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://addons.mozilla.org"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/icedove"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2720"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the icedove packages.

For the stable distribution (wheezy), these problems have been fixed
in version 17.0.7-1~deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox onreadystatechange Event DocumentViewerImpl Use After Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"calendar-google-provider", reference:"17.0.7-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"icedove", reference:"17.0.7-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"icedove-dbg", reference:"17.0.7-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"icedove-dev", reference:"17.0.7-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceowl-extension", reference:"17.0.7-1~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
