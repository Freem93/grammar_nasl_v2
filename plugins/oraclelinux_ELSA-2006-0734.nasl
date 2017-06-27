#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisories ELSA-2006-0734 / 
# ELSA-2006-0676.
#

include("compat.inc");

if (description)
{
  script_id(67423);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/07 20:46:55 $");

  script_cve_id("CVE-2006-4253", "CVE-2006-4340", "CVE-2006-4565", "CVE-2006-4566", "CVE-2006-4568", "CVE-2006-4570", "CVE-2006-4571", "CVE-2006-5462", "CVE-2006-5463", "CVE-2006-5464", "CVE-2006-5747", "CVE-2006-5748");
  script_bugtraq_id(19849);
  script_osvdb_id(27974, 27975, 28843, 28844, 28845, 28846, 28847, 28848, 29013, 30300, 30301, 30302, 30303);
  script_xref(name:"RHSA", value:"2006:0676");
  script_xref(name:"RHSA", value:"2006:0734");

  script_name(english:"Oracle Linux 4 : seamonkey (ELSA-2006-0734 / ELSA-2006-0676)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated seamonkey packages that fix several security bugs are now
available for Red Hat Enterprise Linux 4. 

This update has been rated as having critical security impact by the Red
Hat Security Response Team. 

SeaMonkey is an open source Web browser, advanced email and newsgroup
client, IRC chat client, and HTML editor. 

Users of SeaMonkey are advised to upgrade to these erratum packages,
which contains SeaMonkey version 1.0.6 that corrects these issues.


From Red Hat Security Advisory 2006:0734 :

Several flaws were found in the way SeaMonkey processes certain
malformed Javascript code.  A malicious web page could cause the
execution of Javascript code in such a way that could cause SeaMonkey to
crash or execute arbitrary code as the user running SeaMonkey. 
(CVE-2006-5463, CVE-2006-5747, CVE-2006-5748)

Several flaws were found in the way SeaMonkey renders web pages.  A
malicious web page could cause the browser to crash or possibly execute
arbitrary code as the user running SeaMonkey.  (CVE-2006-5464)

A flaw was found in the way SeaMonkey verifies RSA signatures.  For RSA
keys with exponent 3 it is possible for an attacker to forge a signature
that would be incorrectly verified by the NSS library.  SeaMonkey as
shipped trusts several root Certificate Authorities that use exponent 3. 
An attacker could have created a carefully crafted SSL certificate which
be incorrectly trusted when their site was visited by a victim.  This
flaw was previously thought to be fixed in SeaMonkey 1.0.5, however
Ulrich Kuehn discovered the fix was incomplete (CVE-2006-5462)


From Red Hat Security Advisory 2006:0676 :

Two flaws were found in the way SeaMonkey processed certain regular
expressions.  A malicious web page could crash the browser or possibly
execute arbitrary code as the user running SeaMonkey.  (CVE-2006-4565,
CVE-2006-4566)

A flaw was found in the handling of Javascript timed events.  A
malicious web page could crash the browser or possibly execute arbitrary
code as the user running SeaMonkey.  (CVE-2006-4253)

Daniel Bleichenbacher recently described an implementation error in RSA
signature verification.  For RSA keys with exponent 3 it is possible for
an attacker to forge a signature that would be incorrectly verified by
the NSS library.  SeaMonkey as shipped trusts several root Certificate
Authorities that use exponent 3.  An attacker could have created a
carefully crafted SSL certificate which be incorrectly trusted when
their site was visited by a victim.  (CVE-2006-4340)

SeaMonkey did not properly prevent a frame in one domain from injecting
content into a sub-frame that belongs to another domain, which
facilitates website spoofing and other attacks (CVE-2006-4568)

A flaw was found in SeaMonkey Messenger triggered when a HTML message
contained a remote image pointing to a XBL script.  An attacker could
have created a carefully crafted message which would execute Javascript
if certain actions were performed on the email by the recipient, even if
Javascript was disabled.  (CVE-2006-4570)

A number of flaws were found in SeaMonkey.  A malicious web page could
crash the browser or possibly execute arbitrary code as the user running
SeaMonkey.  (CVE-2006-4571)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2006-December/000024.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected seamonkey packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 79, 119, 264);

  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:devhelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-chat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-nss-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/12");
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
if (rpm_check(release:"EL4", cpu:"i386", reference:"devhelp-0.10-0.5.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"devhelp-0.10-0.5.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"devhelp-devel-0.10-0.5.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"devhelp-devel-0.10-0.5.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-1.0.6-0.1.1.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-1.0.6-0.1.1.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-chat-1.0.6-0.1.1.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-chat-1.0.6-0.1.1.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-devel-1.0.6-0.1.1.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-devel-1.0.6-0.1.1.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-dom-inspector-1.0.6-0.1.1.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-dom-inspector-1.0.6-0.1.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-js-debugger-1.0.6-0.1.1.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-js-debugger-1.0.6-0.1.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-mail-1.0.6-0.1.1.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-mail-1.0.6-0.1.1.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-nspr-1.0.6-0.1.1.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-nspr-1.0.6-0.1.1.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-nspr-devel-1.0.6-0.1.1.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-nspr-devel-1.0.6-0.1.1.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-nss-1.0.6-0.1.1.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-nss-1.0.6-0.1.1.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-nss-devel-1.0.6-0.1.1.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-nss-devel-1.0.6-0.1.1.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

