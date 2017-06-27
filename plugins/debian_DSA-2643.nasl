#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2643. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65228);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/02/16 15:37:39 $");

  script_cve_id("CVE-2013-1640", "CVE-2013-1652", "CVE-2013-1653", "CVE-2013-1654", "CVE-2013-1655", "CVE-2013-2274", "CVE-2013-2275");
  script_osvdb_id(91222, 91223, 91224, 91225, 91226, 91227, 91228);
  script_xref(name:"DSA", value:"2643");

  script_name(english:"Debian DSA-2643-1 : puppet - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in Puppet, a centralized
configuration management system.

  - CVE-2013-1640
    An authenticated malicious client may request its
    catalog from the puppet master, and cause the puppet
    master to execute arbitrary code. The puppet master must
    be made to invoke the 'template' or 'inline_template'
    functions during catalog compilation.

  - CVE-2013-1652
    An authenticated malicious client may retrieve catalogs
    from the puppet master that it is not authorized to
    access. Given a valid certificate and private key, it is
    possible to construct an HTTP GET request that will
    return a catalog for an arbitrary client.

  - CVE-2013-1653
    An authenticated malicious client may execute arbitrary
    code on Puppet agents that accept kick connections.
    Puppet agents are not vulnerable in their default
    configuration. However, if the Puppet agent is
    configured to listen for incoming connections, e.g.
    listen = true, and the agent's auth.conf allows access
    to the 'run' REST endpoint, then an authenticated client
    can construct an HTTP PUT request to execute arbitrary
    code on the agent. This issue is made worse by the fact
    that puppet agents typically run as root.

  - CVE-2013-1654
    A bug in Puppet allows SSL connections to be downgraded
    to SSLv2, which is known to contain design flaw
    weaknesses. This affects SSL connections between puppet
    agents and master, as well as connections that puppet
    agents make to third-party servers that accept SSLv2
    connections. Note that SSLv2 is disabled since OpenSSL
    1.0.

  - CVE-2013-1655
    An unauthenticated malicious client may send requests to
    the puppet master, and have the master load code in an
    unsafe manner. It only affects users whose puppet
    masters are running ruby 1.9.3 and above.

  - CVE-2013-2274
    An authenticated malicious client may execute arbitrary
    code on the puppet master in its default configuration.
    Given a valid certificate and private key, a client can
    construct an HTTP PUT request that is authorized to save
    the client's own report, but the request will actually
    cause the puppet master to execute arbitrary code.

  - CVE-2013-2275
    The default auth.conf allows an authenticated node to
    submit a report for any other node, which is a problem
    for compliance. It has been made more restrictive by
    default so that a node is only allowed to save its own
    report."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1653"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2274"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/puppet"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2643"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the puppet packages.

For the stable distribution (squeeze), these problems have been fixed
in version 2.6.2-5+squeeze7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:puppet");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"puppet", reference:"2.6.2-5+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"puppet-common", reference:"2.6.2-5+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"puppet-el", reference:"2.6.2-5+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"puppet-testsuite", reference:"2.6.2-5+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"puppetmaster", reference:"2.6.2-5+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"vim-puppet", reference:"2.6.2-5+squeeze7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
