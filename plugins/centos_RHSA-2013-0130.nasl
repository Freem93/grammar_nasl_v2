#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0130 and 
# CentOS Errata and Security Advisory 2013:0130 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(63575);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/17 21:12:10 $");

  script_cve_id("CVE-2008-0455", "CVE-2008-0456", "CVE-2012-2687");
  script_bugtraq_id(27409, 55131);
  script_osvdb_id(41018, 41019, 84818);
  script_xref(name:"RHSA", value:"2013:0130");

  script_name(english:"CentOS 5 : httpd (CESA-2013:0130)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated httpd packages that fix multiple security issues, various
bugs, and add enhancements are now available for Red Hat Enterprise
Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The httpd packages contain the Apache HTTP Server (httpd), which is
the namesake project of The Apache Software Foundation.

Input sanitization flaws were found in the mod_negotiation module. A
remote attacker able to upload or create files with arbitrary names in
a directory that has the MultiViews options enabled, could use these
flaws to conduct cross-site scripting and HTTP response splitting
attacks against users visiting the site. (CVE-2008-0455,
CVE-2008-0456, CVE-2012-2687)

Bug fixes :

* Previously, no check was made to see if the
/etc/pki/tls/private/localhost.key file was a valid key prior to
running the '%post' script for the 'mod_ssl' package. Consequently,
when /etc/pki/tls/certs/localhost.crt did not exist and
'localhost.key' was present but invalid, upgrading the Apache HTTP
Server daemon (httpd) with mod_ssl failed. The '%post' script has been
fixed to test for an existing SSL key. As a result, upgrading httpd
with mod_ssl now proceeds as expected. (BZ#752618)

* The 'mod_ssl' module did not support operation under FIPS mode.
Consequently, when operating Red Hat Enterprise Linux 5 with FIPS mode
enabled, httpd failed to start. An upstream patch has been applied to
disable non-FIPS functionality if operating under FIPS mode and httpd
now starts as expected. (BZ#773473)

* Prior to this update, httpd exit status codes were not Linux
Standard Base (LSB) compliant. When the command 'service httpd reload'
was run and httpd failed, the exit status code returned was '0' and
not in the range 1 to 6 as expected. A patch has been applied to the
init script and httpd now returns '1' as an exit status code.
(BZ#783242)

* Chunked Transfer Coding is described in RFC 2616. Previously, the
Apache server did not correctly handle a chunked encoded POST request
with a 'chunk-size' or 'chunk-extension' value of 32 bytes or more.
Consequently, when such a POST request was made the server did not
respond. An upstream patch has been applied and the problem no longer
occurs. (BZ#840845)

* Due to a regression, when mod_cache received a non-cacheable 304
response, the headers were served incorrectly. Consequently,
compressed data could be returned to the client without the cached
headers to indicate the data was compressed. An upstream patch has
been applied to merge response and cached headers before data from the
cache is served to the client. As a result, cached data is now
correctly interpreted by the client. (BZ#845532)

* In a proxy configuration, certain response-line strings were not
handled correctly. If a response-line without a 'description' string
was received from the origin server, for a non-standard status code,
such as the '450' status code, a '500 Internal Server Error' would be
returned to the client. This bug has been fixed so that the original
response line is returned to the client. (BZ#853128)

Enhancements :

* The configuration directive 'LDAPReferrals' is now supported in
addition to the previously introduced 'LDAPChaseReferrals'.
(BZ#727342)

* The AJP support module for 'mod_proxy', 'mod_proxy_ajp', now
supports the 'ProxyErrorOverride' directive. Consequently, it is now
possible to configure customized error pages for web applications
running on a backend server accessed via AJP. (BZ#767890)

* The '%posttrans' scriptlet which automatically restarts the httpd
service after a package upgrade can now be disabled. If the file
/etc/sysconfig/httpd-disable-posttrans exists, the scriptlet will not
restart the daemon. (BZ#833042)

* The output of 'httpd -S' now includes configured alias names for
each virtual host. (BZ#833043)

* New certificate variable names are now exposed by 'mod_ssl' using
the '_DN_userID' suffix, such as 'SSL_CLIENT_S_DN_userID', which use
the commonly used object identifier (OID) definition of 'userID', OID
0.9.2342.19200300.100.1.1. (BZ#840036)

All users of httpd are advised to upgrade to these updated packages,
which fix these issues and add these enhancements."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-January/019175.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c247fc96"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-January/000348.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a019e380"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"httpd-2.2.3-74.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"httpd-devel-2.2.3-74.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"httpd-manual-2.2.3-74.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mod_ssl-2.2.3-74.el5.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
