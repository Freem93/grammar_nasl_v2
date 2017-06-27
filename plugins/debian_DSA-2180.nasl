#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2180. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(52537);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/02/16 15:31:55 $");

  script_cve_id("CVE-2010-1585", "CVE-2011-0051", "CVE-2011-0053", "CVE-2011-0054", "CVE-2011-0055", "CVE-2011-0056", "CVE-2011-0057", "CVE-2011-0059");
  script_bugtraq_id(46643, 46645, 46648, 46650, 46652, 46661, 46663);
  script_osvdb_id(64150, 72437, 72438, 72439, 72440, 72441, 72442, 72443, 72444, 72445, 72446, 72447, 72448, 72449, 72456, 72457, 72458, 72459, 72460, 72465, 72467);
  script_xref(name:"DSA", value:"2180");

  script_name(english:"Debian DSA-2180-1 : iceape - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been found in the Iceape internet suite,
an unbranded version of SeaMonkey :

  - CVE-2010-1585
    Roberto Suggi Liverani discovered that the sanitising
    performed by ParanoidFragmentSink was incomplete.

  - CVE-2011-0051
    Zach Hoffmann discovered that incorrect parsing of
    recursive eval() calls could lead to attackers forcing
    acceptance of a confirmation dialogue.

  - CVE-2011-0053
    Crashes in the layout engine may lead to the execution
    of arbitrary code.

  - CVE-2011-0054
    Christian Holler discovered buffer overflows in the
    JavaScript engine, which could allow the execution of
    arbitrary code.

  - CVE-2011-0055
    'regenrecht' and Igor Bukanov discovered a
    use-after-free error in the JSON-Implementation, which
    could lead to the execution of arbitrary code.

  - CVE-2011-0056
    Christian Holler discovered buffer overflows in the
    JavaScript engine, which could allow the execution of
    arbitrary code.

  - CVE-2011-0057
    Daniel Kozlowski discovered that incorrect memory
    handling the web workers implementation could lead to
    the execution of arbitrary code.

  - CVE-2011-0059
    Peleus Uhley discovered a cross-site request forgery
    risk in the plugin code.

The oldstable distribution (lenny) is not affected. The iceape package
only provides the XPCOM code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0055"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0057"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/iceape"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2180"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the iceape packages.

For the stable distribution (squeeze), this problem has been fixed in
version 2.0.11-3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceape");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"iceape", reference:"2.0.11-3")) flag++;
if (deb_check(release:"6.0", prefix:"iceape-browser", reference:"2.0.11-3")) flag++;
if (deb_check(release:"6.0", prefix:"iceape-chatzilla", reference:"2.0.11-3")) flag++;
if (deb_check(release:"6.0", prefix:"iceape-dbg", reference:"2.0.11-3")) flag++;
if (deb_check(release:"6.0", prefix:"iceape-dev", reference:"2.0.11-3")) flag++;
if (deb_check(release:"6.0", prefix:"iceape-mailnews", reference:"2.0.11-3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
