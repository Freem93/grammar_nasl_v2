#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-130. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14967);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/08/09 10:50:38 $");

  script_cve_id("CVE-2002-0353", "CVE-2002-0401", "CVE-2002-0402", "CVE-2002-0403", "CVE-2002-0404");
  script_bugtraq_id(4604, 4805, 4806, 4807, 4808);
  script_xref(name:"DSA", value:"130");

  script_name(english:"Debian DSA-130-1 : ethereal - remotely triggered memory allocation error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ethereal versions prior to 0.9.3 were vulnerable to an allocation
error in the ASN.1 parser. This can be triggered when analyzing
traffic using the SNMP, LDAP, COPS, or Kerberos protocols in ethereal.
This vulnerability was announced in the ethereal security advisory
enpa-sa-00003. This issue has been corrected in ethereal version
0.8.0-3potato for Debian 2.2 (potato).

Additionally, a number of vulnerabilities were discussed in ethereal
security advisory enpa-sa-00004; the version of ethereal in Debian 2.2
(potato) is not vulnerable to the issues raised in this later
advisory. Users of the not-yet-released woody distribution should
ensure that they are running ethereal 0.9.4-1 or a later version."
  );
  # http://www.ethereal.com/appnotes/enpa-sa-00003.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://ethereal.archive.sunet.se/appnotes/enpa-sa-00003.html"
  );
  # http://www.ethereal.com/appnotes/enpa-sa-00004.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://ethereal.archive.sunet.se/appnotes/enpa-sa-00004.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-130"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the ethereal package immediately."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ethereal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"ethereal", reference:"0.8.0-3potato")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
