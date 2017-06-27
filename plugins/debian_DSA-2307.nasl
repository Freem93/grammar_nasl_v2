#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2307. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56145);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2011-2359", "CVE-2011-2800", "CVE-2011-2818");
  script_bugtraq_id(48960);
  script_osvdb_id(74229, 74251, 74255);
  script_xref(name:"DSA", value:"2307");

  script_name(english:"Debian DSA-2307-1 : chromium-browser - several vulnerabilities");
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

  - CVE-2011-2818
    Use-after-free vulnerability in Google Chrome allows
    remote attackers to cause a denial of service or
    possibly have unspecified other impact via vectors
    related to display box rendering.

  - CVE-2011-2800
    Google Chrome allows remote attackers to obtain
    potentially sensitive information about client-side
    redirect targets via a crafted website.

  - CVE-2011-2359
    Google Chrome does not properly track line boxes during
    rendering, which allows remote attackers to cause a
    denial of service or possibly have unspecified other
    impact via unknown vectors that lead to a 'stale
    pointer'.

Several unauthorised SSL certificates have been found in the wild
issued for the DigiNotar Certificate Authority, obtained through a
security compromise with said company. This update blacklists SSL
certificates issued by DigiNotar-controlled intermediate CAs used by
the Dutch PKIoverheid program."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2359"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2307"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (squeeze), this problem has been fixed in
version 6.0.472.63~r59945-5+squeeze6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/12");
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
if (deb_check(release:"6.0", prefix:"chromium-browser", reference:"6.0.472.63~r59945-5+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"chromium-browser-dbg", reference:"6.0.472.63~r59945-5+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"chromium-browser-inspector", reference:"6.0.472.63~r59945-5+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"chromium-browser-l10n", reference:"6.0.472.63~r59945-5+squeeze6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
