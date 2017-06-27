#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were
# extracted from Debian Security Advisory DSA-2891
#

include("compat.inc");

if (description)
{
  script_id(73256);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/08/10 15:27:29 $");

  script_cve_id(
    "CVE-2013-2031",
    "CVE-2013-2032",
    "CVE-2013-4567",
    "CVE-2013-4568",
    "CVE-2013-4572",
    "CVE-2013-6452",
    "CVE-2013-6453",
    "CVE-2013-6454",
    "CVE-2013-6472",
    "CVE-2014-1610",
    "CVE-2014-2665"
  );
  script_bugtraq_id(
    59594,
    59595,
    63757,
    63760,
    63761,
    65003,
    65223,
    66600
  );
  script_osvdb_id(
    92897,
    92898,
    99943,
    99970,
    102251,
    102293,
    102296,
    102348,
    102630,
    102631,
    105088
  );
  script_xref(name:"DSA", value:"2891");

  script_name(english:"Debian DSA-2891-1 : mediawiki, mediawiki-extensions Multiple Vulnerabilities");
  script_summary(english:"Checks the dpkg output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian host is missing a security update. It is, therefore,
affected by multiple vulnerabilities in MediaWiki :

  - A cross-site scripting (XSS) vulnerability exists due to
    a failure to validate input before returning it to the
    user. An unauthenticated, remote attacker can exploit
    this, via specially crafted SVG files, to execute
    arbitrary script code in the user's browser session.
    (CVE-2013-2031)

  - A flaw exists in the password blocking mechanism due to
    two different tools being used to block password change
    requests, these being Special:PasswordReset and
    Special:ChangePassword, either of which may be bypassed
    by the method the other prevents. A remote attacker can
    exploit this issue to change passwords. (CVE-2013-2032)

  - Multiple flaws exist in Sanitizer::checkCss due to the
    improper sanitization of user-supplied input. An
    unauthenticated, remote attacker can exploit these to
    bypass the blacklist. (CVE-2013-4567, CVE-2013-4568)

  - A flaw exists due to multiple users being granted the
    same session ID within HTTP headers. A remote attacker
    can exploit this to authenticate as another random
    user. (CVE-2013-4572)

  - A cross-site scripting (XSS) vulnerability exists in the
    /includes/libs/XmlTypeCheck.php script due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted XSL file, to execute arbitrary script code in
    the user's browser session. (CVE-2013-6452)

  - A flaw exists in the /includes/upload/UploadBase.php
    script due to a failure to apply SVG sanitization when
    XML files are read as invalid. An unauthenticated,
    remote attacker can exploit this to upload non-sanitized
    XML files, resulting in an unspecified impact.
    (CVE-2013-6453)

  - A stored cross-site (XSS) scripting vulnerability exists
    in the /includes/Sanitizer.php script due to a failure
    to properly validate the '-o-link' attribute before
    returning it to users. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in the user's
    browser session. (CVE-2013-6454)

  - A flaw exists in the log API within the
    /includes/api/ApiQueryLogEvents.php script that allows
    an unauthenticated, remote attacker to disclose
    potentially sensitive information regarding deleted
    pages. (CVE-2013-6472)

  - Multiple flaws exist in the PdfHandler_body.php,
    DjVu.php, Bitmap.php, and ImageHandler.php scripts when
    DjVu or PDF file upload support is enabled due to
    improper sanitization of user-supplied input. An
    authenticated, remote attacker can exploit these, via
    the use of shell metacharacters, to execute execute
    arbitrary shell commands. (CVE-2014-1610)

  - A cross-site request forgery (XSRF) vulnerability exists
    in the includes/specials/SpecialChangePassword.php
    script due to a failure to properly handle a correctly
    authenticated but unintended login attempt. An
    unauthenticated, remote attacker, by convincing a user
    to follow a specially crafted link, can exploit this to
    reset the user's password. (CVE-2014-2665)");
  script_set_attribute(attribute:"see_also", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=729629");
  script_set_attribute(attribute:"see_also", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=706601");
  script_set_attribute(attribute:"see_also", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=742857");
  script_set_attribute(attribute:"see_also", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=742857");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2013-2031");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2013-2032");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2013-4567");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2013-4568");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2013-4572");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2013-6452");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2013-6453");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2013-6454");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2013-6472");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2014-1610");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2014-2665");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/wheezy/mediawiki");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/wheezy/mediawiki-extensions");
  script_set_attribute(attribute:"see_also", value:"http://www.debian.org/security/2014/dsa-2891");
  script_set_attribute(attribute:"solution", value:
"Upgrade the mediawiki packages. For the stable distribution (wheezy),
these issues have been fixed in version 1:1.19.14+dfsg-0+deb7u1 of the
mediawiki package and version 3.5~deb7u1 of the mediawiki-extensions
package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"MediaWiki thumb.php page Parameter Remote Shell Command Injection");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MediaWiki Thumb.php Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mediawiki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mediawiki-extensions");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include("audit.inc");
include("debian_package.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
oslevel = get_kb_item("Host/Debian/release"); 
if (empty_or_null(oslevel)) audit(AUDIT_OS_NOT, "Debian");
if (oslevel !~ "^7\.") audit(AUDIT_OS_NOT, "Debian 7", "Debian " + oslevel);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"7.0", prefix:"mediawiki", reference:"1:1.19.14+dfsg-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mediawiki-extensions", reference:"3.5~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mediawiki-extensions-base", reference:"3.5~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mediawiki-extensions-collection", reference:"3.5~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mediawiki-extensions-geshi", reference:"3.5~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mediawiki-extensions-graphviz", reference:"3.5~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mediawiki-extensions-ldapauth", reference:"3.5~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mediawiki-extensions-openid", reference:"3.5~deb7u1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    xss        : TRUE,
    xsrf       : TRUE,
    extra      : deb_report_get()
  );
}
else audit(AUDIT_HOST_NOT, "affected");
