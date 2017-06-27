#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2736. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69313);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:43:09 $");

  script_cve_id("CVE-2013-4206", "CVE-2013-4207", "CVE-2013-4208", "CVE-2013-4852");
  script_bugtraq_id(61599, 61644, 61645, 61649);
  script_xref(name:"DSA", value:"2736");

  script_name(english:"Debian DSA-2736-1 : putty - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities where discovered in PuTTY, a Telnet/SSH client
for X. The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2013-4206
    Mark Wooding discovered a heap-corrupting buffer
    underrun bug in the modmul function which performs
    modular multiplication. As the modmul function is called
    during validation of any DSA signature received by
    PuTTY, including during the initial key exchange phase,
    a malicious server could exploit this vulnerability
    before the client has received and verified a host key
    signature. An attack to this vulnerability can thus be
    performed by a man-in-the-middle between the SSH client
    and server, and the normal host key protections against
    man-in-the-middle attacks are bypassed.

  - CVE-2013-4207
    It was discovered that non-coprime values in DSA
    signatures can cause a buffer overflow in the
    calculation code of modular inverses when verifying a
    DSA signature. Such a signature is invalid. This bug
    however applies to any DSA signature received by PuTTY,
    including during the initial key exchange phase and thus
    it can be exploited by a malicious server before the
    client has received and verified a host key signature.

  - CVE-2013-4208
    It was discovered that private keys were left in memory
    after being used by PuTTY tools.

  - CVE-2013-4852
    Gergely Eberhardt from SEARCH-LAB Ltd. discovered that
    PuTTY is vulnerable to an integer overflow leading to
    heap overflow during the SSH handshake before
    authentication due to improper bounds checking of the
    length parameter received from the SSH server. A remote
    attacker could use this vulnerability to mount a local
    denial of service attack by crashing the putty client.

Additionally this update backports some general proactive potentially
security-relevant tightening from upstream."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=718779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4208"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4852"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4607"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/putty"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/putty"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2736"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the putty packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 0.60+2010-02-20-1+squeeze2. This update also provides
a fix for CVE-2011-4607, which was fixed for stable already.

For the stable distribution (wheezy), these problems have been fixed
in version 0.62-9+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:putty");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/13");
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
if (deb_check(release:"6.0", prefix:"pterm", reference:"0.60+2010-02-20-1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"putty", reference:"0.60+2010-02-20-1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"putty-doc", reference:"0.60+2010-02-20-1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"putty-tools", reference:"0.60+2010-02-20-1+squeeze2")) flag++;
if (deb_check(release:"7.0", prefix:"pterm", reference:"0.62-9+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"putty", reference:"0.62-9+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"putty-doc", reference:"0.62-9+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"putty-tools", reference:"0.62-9+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
