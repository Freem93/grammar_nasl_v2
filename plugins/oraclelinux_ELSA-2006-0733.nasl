#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisories ELSA-2006-0733 / 
# ELSA-2006-0675 / ELSA-2006-0610. 
#

include("compat.inc");

if (description)
{
  script_id(67422);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/07 20:46:55 $");

  script_cve_id("CVE-2006-2776", "CVE-2006-2778", "CVE-2006-2779", "CVE-2006-2780", "CVE-2006-2782", "CVE-2006-2783", "CVE-2006-2784", "CVE-2006-2785", "CVE-2006-2786", "CVE-2006-2787", "CVE-2006-2788", "CVE-2006-3113", "CVE-2006-3677", "CVE-2006-3801", "CVE-2006-3802", "CVE-2006-3803", "CVE-2006-3805", "CVE-2006-3806", "CVE-2006-3807", "CVE-2006-3808", "CVE-2006-3809", "CVE-2006-3810", "CVE-2006-3811", "CVE-2006-3812", "CVE-2006-4253", "CVE-2006-4340", "CVE-2006-4565", "CVE-2006-4566", "CVE-2006-4567", "CVE-2006-4568", "CVE-2006-4569", "CVE-2006-4571", "CVE-2006-5462", "CVE-2006-5463", "CVE-2006-5464", "CVE-2006-5747", "CVE-2006-5748");
  script_bugtraq_id(19849);
  script_osvdb_id(26299, 26300, 26301, 26302, 26303, 26304, 26305, 26306, 26307, 26308, 26309, 26310, 26311, 26313, 26314, 27558, 27559, 27560, 27561, 27562, 27564, 27565, 27566, 27567, 27568, 27569, 27570, 27571, 27572, 27573, 27574, 27575, 27576, 27577, 27974, 27975, 28843, 28844, 28845, 28846, 28847, 28848, 29013, 30300, 30301, 30302, 30303);
  script_xref(name:"RHSA", value:"2006:0610");
  script_xref(name:"RHSA", value:"2006:0675");
  script_xref(name:"RHSA", value:"2006:0733");

  script_name(english:"Oracle Linux 4 : firefox (ELSA-2006-0733 / ELSA-2006-0675 / ELSA-2006-0610)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix several security bugs are now
available for Red Hat Enterprise Linux 4. 

This update has been rated as having critical security impact by the Red
Hat Security Response Team. 

Mozilla Firefox is an open source Web browser. 

Users of Firefox are advised to upgrade to these erratum packages, which
contain Firefox version 1.5.0.8 that corrects these issues. 


From Red Hat Security Advisory 2006:0733 :

Several flaws were found in the way Firefox processes certain malformed
Javascript code.  A malicious web page could cause the execution of
Javascript code in such a way that could cause Firefox to crash or
execute arbitrary code as the user running Firefox.  (CVE-2006-5463,
CVE-2006-5747, CVE-2006-5748)

Several flaws were found in the way Firefox renders web pages.  A
malicious web page could cause the browser to crash or possibly execute
arbitrary code as the user running Firefox.  (CVE-2006-5464)

A flaw was found in the way Firefox verifies RSA signatures.  For RSA
keys with exponent 3 it is possible for an attacker to forge a signature
that would be incorrectly verified by the NSS library.  Firefox as
shipped trusts several root Certificate Authorities that use exponent 3. 
An attacker could have created a carefully crafted SSL certificate which
be incorrectly trusted when their site was visited by a victim.  This
flaw was previously thought to be fixed in Firefox 1.5.0.7, however
Ulrich Kuehn discovered the fix was incomplete (CVE-2006-5462)


From Red Hat Security Advisory 2006:0675 :

Two flaws were found in the way Firefox processed certain regular
expressions.  A malicious web page could crash the browser or possibly
execute arbitrary code as the user running Firefox.  (CVE-2006-4565,
CVE-2006-4566)

A number of flaws were found in Firefox.  A malicious web page could
crash the browser or possibly execute arbitrary code as the user running
Firefox.  (CVE-2006-4571)

A flaw was found in the handling of Javascript timed events.  A
malicious web page could crash the browser or possibly execute arbitrary
code as the user running Firefox.  (CVE-2006-4253)

Daniel Bleichenbacher recently described an implementation error in RSA
signature verification.  For RSA keys with exponent 3 it is possible for
an attacker to forge a signature that would be incorrectly verified by
the NSS library.  Firefox as shipped trusts several root Certificate
Authorities that use exponent 3.  An attacker could have created a
carefully crafted SSL certificate which be incorrectly trusted when
their site was visited by a victim.  (CVE-2006-4340)

A flaw was found in the Firefox auto-update verification system.  An
attacker who has the ability to spoof a victim's DNS could get Firefox
to download and install malicious code.  In order to exploit this issue
an attacker would also need to get a victim to previously accept an
unverifiable certificate.  (CVE-2006-4567)

Firefox did not properly prevent a frame in one domain from injecting
content into a sub-frame that belongs to another domain, which
facilitates website spoofing and other attacks (CVE-2006-4568)

Firefox did not load manually opened, blocked popups in the right domain
context, which could lead to cross-site scripting attacks.  In order to
exploit this issue an attacker would need to find a site which would
frame their malicious page and convince the user to manually open a
blocked popup.  (CVE-2006-4569)


From Red Hat Security Advisory 2006:0610 :

The Mozilla Foundation has discontinued support for the Mozilla Firefox
1.0 branch.  This update deprecates the Mozilla Firefox 1.0 branch in
Red Hat Enterprise Linux 4 in favor of the supported Mozilla Firefox 1.5
branch. 

This update also resolves a number of outstanding Firefox security
issues :

Several flaws were found in the way Firefox processed certain javascript
actions.  A malicious web page could execute arbitrary javascript
instructions with the permissions of 'chrome', allowing the page to
steal sensitive information or install browser malware.  (CVE-2006-2776,
CVE-2006-2784, CVE-2006-2785, CVE-2006-2787, CVE-2006-3807,
CVE-2006-3809, CVE-2006-3812)

Several denial of service flaws were found in the way Firefox processed
certain web content.  A malicious web page could crash the browser or
possibly execute arbitrary code as the user running Firefox. 
(CVE-2006-2779, CVE-2006-2780, CVE-2006-3801, CVE-2006-3677,
CVE-2006-3113, CVE-2006-3803, CVE-2006-3805, CVE-2006-3806,
CVE-2006-3811)

A cross-site scripting flaw was found in the way Firefox processed
Unicode Byte-Order-Mark (BOM) markers in UTF-8 web pages.  A malicious
web page could execute a script within the browser that a web input
sanitizer could miss due to a malformed 'script' tag.  (CVE-2006-2783)

Several flaws were found in the way Firefox processed certain javascript
actions.  A malicious web page could conduct a cross-site scripting
attack or steal sensitive information (such as cookies owned by other
domains).  (CVE-2006-3802, CVE-2006-3810)

A form file upload flaw was found in the way Firefox handled javascript
input object mutation.  A malicious web page could upload an arbitrary
local file at form submission time without user interaction. 
(CVE-2006-2782)

A denial of service flaw was found in the way Firefox called the
crypto.signText() javascript function.  A malicious web page could crash
the browser if the victim had a client certificate loaded. 
(CVE-2006-2778)

Two HTTP response smuggling flaws were found in the way Firefox
processed certain invalid HTTP response headers.  A malicious web site
could return specially crafted HTTP response headers which may bypass
HTTP proxy restrictions.  (CVE-2006-2786)

A flaw was found in the way Firefox processed Proxy AutoConfig scripts. 
A malicious Proxy AutoConfig server could execute arbitrary javascript
instructions with the permissions of 'chrome', allowing the page to
steal sensitive information or install browser malware.  (CVE-2006-3808)

A double free flaw was found in the way the nsIX509::getRawDER method
was called.  If a victim visited a carefully crafted web page, it was
possible to execute arbitrary code as the user running Firefox. 
(CVE-2006-2788)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2006-December/000023.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected firefox package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Suite/Firefox Navigator Object Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 79, 94, 119, 264);

  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);


flag = 0;
if (rpm_check(release:"EL4", cpu:"i386", reference:"firefox-1.5.0.8-0.1.1.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"firefox-1.5.0.8-0.1.1.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

