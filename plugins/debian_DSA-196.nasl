#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-196. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(15033);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2002-0029", "CVE-2002-1219", "CVE-2002-1220", "CVE-2002-1221");
  script_bugtraq_id(6159, 6160, 6161);
  script_xref(name:"CERT", value:"229595");
  script_xref(name:"CERT", value:"542971");
  script_xref(name:"CERT", value:"581682");
  script_xref(name:"CERT", value:"844360");
  script_xref(name:"CERT", value:"852283");
  script_xref(name:"DSA", value:"196");

  script_name(english:"Debian DSA-196-1 : bind - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"[Bind version 9, the bind9 package, is not affected by these
problems.]

ISS X-Force has discovered several serious vulnerabilities in the
Berkeley Internet Name Domain Server (BIND). BIND is the most common
implementation of the DNS (Domain Name Service) protocol, which is
used on the vast majority of DNS servers on the Internet. DNS is a
vital Internet protocol that maintains a database of easy-to-remember
domain names (host names) and their corresponding numerical IP
addresses.

Circumstantial evidence suggests that the Internet Software Consortium
(ISC), maintainers of BIND, was made aware of these issues in
mid-October. Distributors of Open Source operating systems, including
Debian, were notified of these vulnerabilities via CERT about 12 hours
before the release of the advisories on November 12th. This
notification did not include any details that allowed us to identify
the vulnerable code, much less prepare timely fixes.

Unfortunately ISS and the ISC released their security advisories with
only descriptions of the vulnerabilities, without any patches. Even
though there were no signs that these exploits are known to the
black-hat community, and there were no reports of active attacks, such
attacks could have been developed in the meantime - with no fixes
available.

We can all express our regret at the inability of the ironically named
Internet Software Consortium to work with the Internet community in
handling this problem. Hopefully this will not become a model for
dealing with security issues in the future.

The Common Vulnerabilities and Exposures (CVE) project identified the
following vulnerabilities :

  - CAN-2002-1219: A buffer overflow in BIND 8 versions
    8.3.3 and earlier allows a remote attacker to execute
    arbitrary code via a certain DNS server response
    containing SIG resource records (RR). This buffer
    overflow can be exploited to obtain access to the victim
    host under the account the named process is running
    with, usually root.
  - CAN-2002-1220: BIND 8 versions 8.3.x through 8.3.3
    allows a remote attacker to cause a denial of service
    (termination due to assertion failure) via a request for
    a subdomain that does not exist, with an OPT resource
    record with a large UDP payload size.

  - CAN-2002-1221: BIND 8 versions 8.x through 8.3.3 allows
    a remote attacker to cause a denial of service (crash)
    via SIG RR elements with invalid expiry times, which are
    removed from the internal BIND database and later cause
    a null dereference.

These problems have been fixed in version 8.3.3-2.0woody1 for the
current stable distribution (woody), in version 8.2.3-0.potato.3 for
the previous stable distribution (potato) and in version 8.3.3-3 for
the unstable distribution (sid). The fixed packages for unstable will
enter the archive today."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-196"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bind package immediately, update to bind9, or switch to
another DNS server implementation."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"bind", reference:"8.2.3-0.potato.3")) flag++;
if (deb_check(release:"2.2", prefix:"bind-dev", reference:"8.2.3-0.potato.3")) flag++;
if (deb_check(release:"2.2", prefix:"bind-doc", reference:"8.2.3-0.potato.3")) flag++;
if (deb_check(release:"2.2", prefix:"dnsutils", reference:"8.2.3-0.potato.3")) flag++;
if (deb_check(release:"2.2", prefix:"task-dns-server", reference:"8.2.3-0.potato.3")) flag++;
if (deb_check(release:"3.0", prefix:"bind", reference:"8.3.3-2.0woody1")) flag++;
if (deb_check(release:"3.0", prefix:"bind-dev", reference:"8.3.3-2.0woody1")) flag++;
if (deb_check(release:"3.0", prefix:"bind-doc", reference:"8.3.3-2.0woody1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
