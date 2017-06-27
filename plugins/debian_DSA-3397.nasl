#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3397. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86833);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/06 20:25:08 $");

  script_cve_id("CVE-2015-4141", "CVE-2015-4142", "CVE-2015-4143", "CVE-2015-4144", "CVE-2015-4145", "CVE-2015-4146", "CVE-2015-5310", "CVE-2015-5314", "CVE-2015-5315", "CVE-2015-5316", "CVE-2015-8041");
  script_osvdb_id(121654, 121655, 121656, 121657, 121658, 121659, 121662, 121663, 124323, 130094, 130096, 130113);
  script_xref(name:"DSA", value:"3397");

  script_name(english:"Debian DSA-3397-1 : wpa - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in wpa_supplicant and
hostapd. The Common Vulnerabilities and Exposures project identifies
the following problems :

  - CVE-2015-4141
    Kostya Kortchinsky of the Google Security Team
    discovered a vulnerability in the WPS UPnP function with
    HTTP chunked transfer encoding which may result in a
    denial of service.

  - CVE-2015-4142
    Kostya Kortchinsky of the Google Security Team
    discovered a vulnerability in the WMM Action frame
    processing which may result in a denial of service.

  - CVE-2015-4143 CVE-2015-4144 CVE-2015-4145 CVE-2015-4146
    Kostya Kortchinsky of the Google Security Team
    discovered that EAP-pwd payload is not properly
    validated which may result in a denial of service.

  - CVE-2015-5310
    Jouni Malinen discovered a flaw in the WMM Sleep Mode
    Response frame processing. A remote attacker can take
    advantage of this flaw to mount a denial of service.

  - CVE-2015-5314 CVE-2015-5315
    Jouni Malinen discovered a flaw in the handling of
    EAP-pwd messages which may result in a denial of
    service.

  - CVE-2015-5316
    Jouni Malinen discovered a flaw in the handling of
    EAP-pwd Confirm messages which may result in a denial of
    service.

  - CVE-2015-8041
    Incomplete WPS and P2P NFC NDEF record payload length
    validation may result in a denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=787371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=787372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=787373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=795740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=804707"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=804708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=804710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4144"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4146"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5310"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5316"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/wpa"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/wpa"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3397"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wpa packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 1.0-3+deb7u3. The oldstable distribution (wheezy) is
only affected by CVE-2015-4141, CVE-2015-4142, CVE-2015-4143 and
CVE-2015-8041.

For the stable distribution (jessie), these problems have been fixed
in version 2.3-1+deb8u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wpa");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/11");
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
if (deb_check(release:"7.0", prefix:"hostapd", reference:"1.0-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"wpagui", reference:"1.0-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"wpasupplicant", reference:"1.0-3+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"wpasupplicant-udeb", reference:"1.0-3+deb7u3")) flag++;
if (deb_check(release:"8.0", prefix:"hostapd", reference:"2.3-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"wpagui", reference:"2.3-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"wpasupplicant", reference:"2.3-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"wpasupplicant-udeb", reference:"2.3-1+deb8u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
