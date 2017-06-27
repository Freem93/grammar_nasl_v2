#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3265. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83748);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/09/12 13:37:17 $");

  script_cve_id("CVE-2014-2681", "CVE-2014-2682", "CVE-2014-2683", "CVE-2014-2684", "CVE-2014-2685", "CVE-2014-4914", "CVE-2014-8088", "CVE-2014-8089", "CVE-2015-3154");
  script_bugtraq_id(66358, 68031, 70011, 70378, 74561);
  script_osvdb_id(104286, 104330, 104331, 105276, 108047, 111466, 111721, 121821);
  script_xref(name:"DSA", value:"3265");

  script_name(english:"Debian DSA-3265-1 : zendframework - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in Zend Framework, a PHP
framework. Except for CVE-2015-3154, all these issues were already
fixed in the version initially shipped with Jessie.

  - CVE-2014-2681
    Lukas Reschke reported a lack of protection against XML
    External Entity injection attacks in some functions.
    This fix extends the incomplete one from CVE-2012-5657.

  - CVE-2014-2682
    Lukas Reschke reported a failure to consider that the
    libxml_disable_entity_loader setting is shared among
    threads in the PHP-FPM case. This fix extends the
    incomplete one from CVE-2012-5657.

  - CVE-2014-2683
    Lukas Reschke reported a lack of protection against XML
    Entity Expansion attacks in some functions. This fix
    extends the incomplete one from CVE-2012-6532.

  - CVE-2014-2684
    Christian Mainka and Vladislav Mladenov from the
    Ruhr-University Bochum reported an error in the
    consumer's verify method that lead to acceptance of
    wrongly sourced tokens.

  - CVE-2014-2685
    Christian Mainka and Vladislav Mladenov from the
    Ruhr-University Bochum reported a specification
    violation in which signing of a single parameter is
    incorrectly considered sufficient.

  - CVE-2014-4914
    Cassiano Dal Pizzol discovered that the implementation
    of the ORDER BY SQL statement in Zend_Db_Select contains
    a potential SQL injection when the query string passed
    contains parentheses.

  - CVE-2014-8088
    Yury Dyachenko at Positive Research Center identified
    potential XML eXternal Entity injection vectors due to
    insecure usage of PHP's DOM extension.

  - CVE-2014-8089
    Jonas Sandstrom discovered a SQL injection vector when
    manually quoting value for sqlsrv extension, using null
    byte.

  - CVE-2015-3154
    Filippo Tessarotto and Maks3w reported potential CRLF
    injection attacks in mail and HTTP headers."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=743175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=754201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-2681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-5657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-2682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-5657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-2683"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-6532"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-2684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-2685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-4914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-8088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-8089"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/zendframework"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/zendframework"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3265"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the zendframework packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 1.11.13-1.1+deb7u1.

For the stable distribution (jessie), these problems have been fixed
in version 1.12.9+dfsg-2+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zendframework");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"zendframework", reference:"1.11.13-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"zendframework-bin", reference:"1.11.13-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"zendframework-resources", reference:"1.11.13-1.1+deb7u1")) flag++;
if (deb_check(release:"8.0", prefix:"zendframework", reference:"1.12.9+dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"zendframework-bin", reference:"1.12.9+dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"zendframework-resources", reference:"1.12.9+dfsg-2+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
