#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2192. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52674);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2011-0779", "CVE-2011-1290");
  script_bugtraq_id(46144, 46849);
  script_osvdb_id(70985, 71182);
  script_xref(name:"DSA", value:"2192");

  script_name(english:"Debian DSA-2192-1 : chromium-browser - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in the Chromium browser. The
Common Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2011-0779
    Google Chrome before 9.0.597.84 does not properly handle
    a missing key in an extension, which allows remote
    attackers to cause a denial of service (application
    crash) via a crafted extension.

  - CVE-2011-1290
    Integer overflow in WebKit allows remote attackers to
    execute arbitrary code via unknown vectors, as
    demonstrated by Vincenzo Iozzo, Willem Pinckaers, and
    Ralf-Philipp Weinmann during a Pwn2Own competition at
    CanSecWest 2011."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1290"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2192"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (squeeze), these problems have been fixed
in version 6.0.472.63~r59945-5+squeeze4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/16");
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
if (deb_check(release:"6.0", prefix:"chromium-browser", reference:"6.0.472.63~r59945-5+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"chromium-browser-dbg", reference:"6.0.472.63~r59945-5+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"chromium-browser-inspector", reference:"6.0.472.63~r59945-5+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"chromium-browser-l10n", reference:"6.0.472.63~r59945-5+squeeze4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
