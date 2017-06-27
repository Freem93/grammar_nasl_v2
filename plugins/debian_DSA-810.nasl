#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-810. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(19685);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2014/05/22 11:11:54 $");

  script_cve_id("CVE-2004-0718", "CVE-2005-1937", "CVE-2005-2260", "CVE-2005-2261", "CVE-2005-2263", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2268", "CVE-2005-2269", "CVE-2005-2270", "CVE-2005-2271", "CVE-2005-2272", "CVE-2005-2273", "CVE-2005-2274");
  script_bugtraq_id(14242);
  script_osvdb_id(17397, 17913, 17942, 17964, 17966, 17968, 17969, 17970, 59834, 77534, 79188, 79395);
  script_xref(name:"DSA", value:"810");

  script_name(english:"Debian DSA-810-1 : mozilla - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several problems have been discovered in Mozilla, the web browser of
the Mozilla suite. Since the usual praxis of backporting apparently
does not work for this package, this update is basically version
1.7.10 with the version number rolled back, and hence still named
1.7.8. The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CAN-2004-0718, CAN-2005-1937
    A vulnerability has been discovered in Mozilla that
    allows remote attackers to inject arbitrary JavaScript
    from one page into the frameset of another site.

  - CAN-2005-2260

    The browser user interface does not properly distinguish
    between user-generated events and untrusted synthetic
    events, which makes it easier for remote attackers to
    perform dangerous actions that normally could only be
    performed manually by the user.

  - CAN-2005-2261

    XML scripts ran even when JavaScript disabled.

  - CAN-2005-2263

    It is possible for a remote attacker to execute a
    callback function in the context of another domain (i.e.
    frame).

  - CAN-2005-2265

    Missing input sanitising of InstallVersion.compareTo()
    can cause the application to crash.

  - CAN-2005-2266

    Remote attackers could steal sensitive information such
    as cookies and passwords from websites by accessing data
    in alien frames.

  - CAN-2005-2268

    It is possible for a JavaScript dialog box to spoof a
    dialog box from a trusted site and facilitates phishing
    attacks.

  - CAN-2005-2269

    Remote attackers could modify certain tag properties of
    DOM nodes that could lead to the execution of arbitrary
    script or code.

  - CAN-2005-2270

    The Mozilla browser family does not properly clone base
    objects, which allows remote attackers to execute
    arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-810"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Mozilla packages.

For the stable distribution (sarge) these problems have been fixed in
version 1.7.8-1sarge2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Suite/Firefox compareTo() Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mozilla");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libnspr-dev", reference:"1.7.8-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libnspr4", reference:"1.7.8-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libnss-dev", reference:"1.7.8-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libnss3", reference:"1.7.8-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla", reference:"1.7.8-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-browser", reference:"1.7.8-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-calendar", reference:"1.7.8-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-chatzilla", reference:"1.7.8-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-dev", reference:"1.7.8-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-dom-inspector", reference:"1.7.8-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-js-debugger", reference:"1.7.8-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-mailnews", reference:"1.7.8-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-psm", reference:"1.7.8-1sarge2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
