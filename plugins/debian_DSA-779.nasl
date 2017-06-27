#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-779. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(19476);
  script_version("$Revision: 1.28 $");
  script_cvs_date("$Date: 2016/05/26 16:04:30 $");

  script_cve_id("CVE-2005-2260", "CVE-2005-2261", "CVE-2005-2262", "CVE-2005-2263", "CVE-2005-2264", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2267", "CVE-2005-2268", "CVE-2005-2269", "CVE-2005-2270", "CVE-2005-2271", "CVE-2005-2272", "CVE-2005-2273", "CVE-2005-2274");
  script_bugtraq_id(14242);
  script_osvdb_id(17397, 17913, 17942, 17964, 17965, 17966, 17967, 17968, 17969, 17970, 17971, 77534, 79188, 79395);
  script_xref(name:"DSA", value:"779");

  script_name(english:"Debian DSA-779-2 : mozilla-firefox - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"We experienced that the update for Mozilla Firefox from DSA 779-1
unfortunately was a regression in several cases.  Since the usual
praxis of backporting apparently does not work, this update is
basically version 1.0.6 with the version number rolled back, and hence
still named 1.0.4-*.  For completeness below is the original advisory
text :

  Several problems have been discovered in Mozilla Firefox, a
  lightweight web browser based on Mozilla. The Common Vulnerabilities
  and Exposures project identifies the following problems :

    - CAN-2005-2260
      The browser user interface does not properly
      distinguish between user-generated events and
      untrusted synthetic events, which makes it easier for
      remote attackers to perform dangerous actions that
      normally could only be performed manually by the user.

    - CAN-2005-2261

      XML scripts ran even when JavaScript disabled.

    - CAN-2005-2262

      The user can be tricked to executing arbitrary
      JavaScript code by using a JavaScript URL as
      wallpaper.

    - CAN-2005-2263

      It is possible for a remote attacker to execute a
      callback function in the context of another domain
      (i.e. frame).

    - CAN-2005-2264

      By opening a malicious link in the sidebar it is
      possible for remote attackers to steal sensitive
      information.

    - CAN-2005-2265

      Missing input sanitising of InstallVersion.compareTo()
      can cause the application to crash.

    - CAN-2005-2266

      Remote attackers could steal sensitive information
      such as cookies and passwords from websites by
      accessing data in alien frames.

    - CAN-2005-2267

      By using standalone applications such as Flash and
      QuickTime to open a javascript: URL, it is possible
      for a remote attacker to steal sensitive information
      and possibly execute arbitrary code.

    - CAN-2005-2268

      It is possible for a JavaScript dialog box to spoof a
      dialog box from a trusted site and facilitates
      phishing attacks.

    - CAN-2005-2269

      Remote attackers could modify certain tag properties
      of DOM nodes that could lead to the execution of
      arbitrary script or code.

    - CAN-2005-2270

      The Mozilla browser family does not properly clone
      base objects, which allows remote attackers to execute
      arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=318061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-779"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Mozilla Firefox packages.

The old stable distribution (woody) is not affected by these problems.

For the stable distribution (sarge) these problems have been fixed in
version 1.0.4-2sarge3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Suite/Firefox compareTo() Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"mozilla-firefox", reference:"1.0.4-2sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-firefox-dom-inspector", reference:"1.0.4-2sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-firefox-gnome-support", reference:"1.0.4-2sarge3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
