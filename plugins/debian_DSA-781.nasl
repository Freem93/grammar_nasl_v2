#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-781. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(19478);
  script_version("$Revision: 1.28 $");
  script_cvs_date("$Date: 2016/05/19 17:45:44 $");

  script_cve_id("CVE-2005-0989", "CVE-2005-1159", "CVE-2005-1160", "CVE-2005-1532", "CVE-2005-2261", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2269", "CVE-2005-2270");
  script_bugtraq_id(14242);
  script_osvdb_id(15682, 15689, 15690, 16605, 17913, 17942, 17968, 17969, 17970, 77534, 79188);
  script_xref(name:"DSA", value:"781");

  script_name(english:"Debian DSA-781-1 : mozilla-thunderbird - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several problems have been discovered in Mozilla Thunderbird, the
standalone mail client of the Mozilla suite. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CAN-2005-0989
    Remote attackers could read portions of heap memory into
    a JavaScript string via the lambda replace method.

  - CAN-2005-1159

    The JavaScript interpreter could be tricked to continue
    execution at the wrong memory address, which may allow
    attackers to cause a denial of service (application
    crash) and possibly execute arbitrary code.

  - CAN-2005-1160

    Remote attackers could override certain properties or
    methods of DOM nodes and gain privileges.

  - CAN-2005-1532

    Remote attackers could override certain properties or
    methods due to missing proper limitation of JavaScript
    eval and Script objects and gain privileges.

  - CAN-2005-2261

    XML scripts ran even when JavaScript disabled.

  - CAN-2005-2265

    Missing input sanitising of InstallVersion.compareTo()
    can cause the application to crash.

  - CAN-2005-2266

    Remote attackers could steal sensitive information such
    as cookies and passwords from websites by accessing data
    in alien frames.

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
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=318728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-781"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Mozilla Thunderbird package.

The old stable distribution (woody) is not affected by these problems
since it does not contain Mozilla Thunderbird packages.

For the stable distribution (sarge) these problems have been fixed in
version 1.0.2-2.sarge1.0.6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Suite/Firefox compareTo() Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/01");
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
if (deb_check(release:"3.1", prefix:"mozilla-thunderbird", reference:"1.0.2-2.sarge1.0.6")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-thunderbird-dev", reference:"1.0.2-2.sarge1.0.6")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-thunderbird-inspector", reference:"1.0.2-2.sarge1.0.6")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-thunderbird-offline", reference:"1.0.2-2.sarge1.0.6")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-thunderbird-typeaheadfind", reference:"1.0.2-2.sarge1.0.6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
