#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3439. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87829);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/06 20:25:08 $");

  script_cve_id("CVE-2016-1231", "CVE-2016-1232");
  script_osvdb_id(132716, 132717);
  script_xref(name:"DSA", value:"3439");

  script_name(english:"Debian DSA-3439-1 : prosody - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities were discovered in Prosody, a lightweight
Jabber/XMPP server. The Common Vulnerabilities and Exposures project
identifies the following issues :

  - CVE-2016-1231
    Kim Alvefur discovered a flaw in Prosody's HTTP
    file-serving module that allows it to serve requests
    outside of the configured public root directory. A
    remote attacker can exploit this flaw to access private
    files including sensitive data. The default
    configuration does not enable the mod_http_files module
    and thus is not vulnerable.

  - CVE-2016-1232
    Thijs Alkemade discovered that Prosody's generation of
    the secret token for server-to-server dialback
    authentication relied upon a weak random number
    generator that was not cryptographically secure. A
    remote attacker can take advantage of this flaw to guess
    at probable values of the secret key and impersonate the
    affected domain to other servers on the network."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/prosody"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/prosody"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3439"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the prosody packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 0.8.2-4+deb7u3.

For the stable distribution (jessie), these problems have been fixed
in version 0.9.7-2+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:prosody");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"prosody", reference:"0.8.2-4+deb7u3")) flag++;
if (deb_check(release:"8.0", prefix:"prosody", reference:"0.9.7-2+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
