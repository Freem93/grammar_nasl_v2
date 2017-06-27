#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2405. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57851);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/02/16 15:31:57 $");

  script_cve_id("CVE-2011-3368", "CVE-2011-3607", "CVE-2011-3639", "CVE-2011-4317", "CVE-2012-0031", "CVE-2012-0053");
  script_bugtraq_id(49957, 50494, 50802, 51407, 51706);
  script_xref(name:"DSA", value:"2405");

  script_name(english:"Debian DSA-2405-1 : apache2 - multiple issues");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been found in the Apache HTTPD Server :

  - CVE-2011-3607 :
    An integer overflow in ap_pregsub() could allow local
    attackers to execute arbitrary code at elevated
    privileges via crafted .htaccess files.

  - CVE-2011-3368 CVE-2011-3639 CVE-2011-4317 :
    The Apache HTTP Server did not properly validate the
    request URI for proxied requests. In certain reverse
    proxy configurations using the ProxyPassMatch directive
    or using the RewriteRule directive with the [P] flag, a
    remote attacker could make the proxy connect to an
    arbitrary server. This could allow the attacker to
    access internal servers that are not otherwise
    accessible from the outside.

  The three CVE ids denote slightly different variants of the same
  issue.

  Note that, even with this issue fixed, it is the responsibility of
  the administrator to ensure that the regular expression replacement
  pattern for the target URI does not allow a client to append
  arbitrary strings to the host or port parts of the target URI. For
  example, the configuration

  ProxyPassMatch ^/mail(.*) http://internal-host$1

  is still insecure and should be replaced by one of the following
  configurations :

  ProxyPassMatch ^/mail(/.*) http://internal-host$1 ProxyPassMatch
  ^/mail/(.*) http://internal-host/$1

  - CVE-2012-0031 :
    An apache2 child process could cause the parent process
    to crash during shutdown. This is a violation of the
    privilege separation between the apache2 processes and
    could potentially be used to worsen the impact of other
    vulnerabilities.

  - CVE-2012-0053 :
    The response message for error code 400 (bad request)
    could be used to expose 'httpOnly' cookies. This could
    allow a remote attacker using cross site scripting to
    steal authentication cookies."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3607"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3368"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/apache2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2405"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the apache2 packages.

For the oldstable distribution (lenny), these problems have been fixed
in version apache2 2.2.9-10+lenny12.

For the stable distribution (squeeze), these problems have been fixed
in version apache2 2.2.16-6+squeeze6

This update also contains updated apache2-mpm-itk packages which have
been recompiled against the updated apache2 packages. The new version
number for the oldstable distribution is 2.2.6-02-1+lenny7. In the
stable distribution, apache2-mpm-itk has the same version number as
apache2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-14-410");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"apache2", reference:"2.2.9-10+lenny12")) flag++;
if (deb_check(release:"6.0", prefix:"apache2", reference:"2.2.16-6+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-dbg", reference:"2.2.16-6+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-doc", reference:"2.2.16-6+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-mpm-event", reference:"2.2.16-6+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-mpm-itk", reference:"2.2.16-6+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-mpm-prefork", reference:"2.2.16-6+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-mpm-worker", reference:"2.2.16-6+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-prefork-dev", reference:"2.2.16-6+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-suexec", reference:"2.2.16-6+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-suexec-custom", reference:"2.2.16-6+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-threaded-dev", reference:"2.2.16-6+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-utils", reference:"2.2.16-6+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"apache2.2-bin", reference:"2.2.16-6+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"apache2.2-common", reference:"2.2.16-6+squeeze6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
