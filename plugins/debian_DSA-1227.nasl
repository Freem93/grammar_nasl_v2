#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1227. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23768);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/26 15:53:37 $");

  script_cve_id("CVE-2006-4310", "CVE-2006-5462", "CVE-2006-5463", "CVE-2006-5464", "CVE-2006-5748");
  script_bugtraq_id(19678, 20957);
  script_osvdb_id(29013, 30300, 30301, 30303, 30759);
  script_xref(name:"CERT", value:"335392");
  script_xref(name:"CERT", value:"390480");
  script_xref(name:"CERT", value:"495288");
  script_xref(name:"CERT", value:"714496");
  script_xref(name:"DSA", value:"1227");

  script_name(english:"Debian DSA-1227-1 : mozilla-thunderbird - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security related problems have been discovered in Mozilla and
derived products such as Mozilla Thunderbird. The Common
Vulnerabilities and Exposures project identifies the following
vulnerabilities :

  - CVE-2006-4310
    Tomas Kempinsky discovered that malformed FTP server
    responses could lead to denial of service.

  - CVE-2006-5462
    Ulrich Kuhn discovered that the correction for a
    cryptographic flaw in the handling of PKCS-1
    certificates was incomplete, which allows the forgery of
    certificates.

  - CVE-2006-5463
    'shutdown' discovered that modification of JavaScript
    objects during execution could lead to the execution of
    arbitrary JavaScript bytecode.

  - CVE-2006-5464
    Jesse Ruderman and Martijn Wargers discovered several
    crashes in the layout engine, which might also allow
    execution of arbitrary code.

  - CVE-2006-5748
    Igor Bukanov and Jesse Ruderman discovered several
    crashes in the JavaScript engine, which might allow
    execution of arbitrary code.

This update also addresses several crashes, which could be triggered
by malicious websites and fixes a regression introduced in the
previous Mozilla update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4310"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-5462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-5463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-5464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-5748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1227"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mozilla-thunderbird package.

For the stable distribution (sarge) these problems have been fixed in
version 1.0.4-2sarge13."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/04");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"mozilla-thunderbird", reference:"1.0.2-2.sarge1.0.8d.1")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-thunderbird-dev", reference:"1.0.2-2.sarge1.0.8d.1")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-thunderbird-inspector", reference:"1.0.2-2.sarge1.0.8d.1")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-thunderbird-offline", reference:"1.0.2-2.sarge1.0.8d.1")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-thunderbird-typeaheadfind", reference:"1.0.2-2.sarge1.0.8d.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
