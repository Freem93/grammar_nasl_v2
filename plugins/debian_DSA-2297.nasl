#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2297. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55942);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/19 17:45:43 $");

  script_cve_id("CVE-2011-0084", "CVE-2011-2378", "CVE-2011-2981", "CVE-2011-2982", "CVE-2011-2983", "CVE-2011-2984");
  script_bugtraq_id(49213, 49214, 49216, 49218, 49219, 49223);
  script_osvdb_id(74581, 74582, 74584, 74585, 74586, 74587);
  script_xref(name:"DSA", value:"2297");

  script_name(english:"Debian DSA-2297-1 : icedove - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Icedove, an unbranded
version of the Thunderbird mail/news client.

  - CVE-2011-0084
    'regenrecht' discovered that incorrect pointer handling
    in the SVG processing code could lead to the execution
    of arbitrary code.

  - CVE-2011-2378
    'regenrecht' discovered that incorrect memory management
    in DOM processing could lead to the execution of
    arbitrary code.

  - CVE-2011-2981
    'moz_bug_r_a_4' discovered a Chrome privilege escalation
    vulnerability in the event handler code.

  - CVE-2011-2982
    Gary Kwong, Igor Bukanov, Nils and Bob Clary discovered
    memory corruption bugs, which may lead to the execution
    of arbitrary code.

  - CVE-2011-2983
    'shutdown' discovered an information leak in the
    handling of RegExp.input.

  - CVE-2011-2984
    'moz_bug_r_a4' discovered a Chrome privilege escalation
    vulnerability.

As indicated in the Lenny (oldstable) release notes, security support
for the Icedove packages in the oldstable needed to be stopped before
the end of the regular Lenny security maintenance life cycle. You are
strongly encouraged to upgrade to stable or switch to a different mail
client."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2983"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/icedove"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2297"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the iceweasel packages.

For the stable distribution (squeeze), this problem has been fixed in
version 3.0.11-1+squeeze4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/23");
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
if (deb_check(release:"6.0", prefix:"icedove", reference:"3.0.11-1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"icedove-dbg", reference:"3.0.11-1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"icedove-dev", reference:"3.0.11-1+squeeze4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
