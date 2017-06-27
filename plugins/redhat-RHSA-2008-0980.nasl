#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0980. The text 
# itself is copyright (C) Red Hat, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(63870);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/10 18:05:23 $");

  script_cve_id("CVE-2007-4324", "CVE-2007-6243", "CVE-2008-3873", "CVE-2008-4401", "CVE-2008-4503", "CVE-2008-4818", "CVE-2008-4819", "CVE-2008-4821", "CVE-2008-4822", "CVE-2008-4823", "CVE-2008-4824", "CVE-2008-5361", "CVE-2008-5362", "CVE-2008-5363");
  script_osvdb_id(51567);
  script_xref(name:"RHSA", value:"2008:0980");

  script_name(english:"RHEL 3 / 4 : flash-plugin (RHSA-2008:0980)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated Adobe Flash Player package that fixes several security
issues is now available for Red Hat Enterprise Linux 3 and 4 Extras.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

[Updated 18th November 2008] This erratum has been updated to include
a reference to the additional CVE-named issue that was not public at
the time of release. The security impact of the erratum has also been
upgraded to Critical. No changes have been made to the packages.

The flash-plugin package contains a Firefox-compatible Adobe Flash
Player Web browser plug-in.

A flaw was found in the way Adobe Flash Player wrote content to the
clipboard. A malicious SWF (Shockwave Flash) file could populate the
clipboard with a URL that could cause the user to accidentally or
mistakenly load an attacker-controlled URL. (CVE-2008-3873)

A flaw was found with Adobe's ActionScript scripting language which
allowed Flash scripts to initiate file uploads and downloads without
user interaction. ActionScript's FileReference.browse and
FileReference.download method calls can now only be initiated via user
interaction, such as through mouse-clicks or key-presses on the
keyboard. (CVE-2008-4401)

A flaw was found in Adobe Flash Player's display of Settings Manager
content. A malicious SWF file could trick the user into
unintentionally or mistakenly clicking a link or a dialog which could
then give the malicious SWF file permission to access the local
machine's camera or microphone. (CVE-2008-4503)

Flaws were found in the way Flash Player restricted the interpretation
and usage of cross-domain policy files. A remote attacker could use
Flash Player to conduct cross-domain and cross-site scripting attacks
(CVE-2007-4324, CVE-2007-6243). This update provides enhanced fixes
for these issues.

Flash Player contains a flaw in the way it interprets HTTP response
headers. An attacker could use this flaw to conduct a cross-site
scripting attack against the user running Flash Player.
(CVE-2008-4818)

A flaw was found in the way Flash Player handles the ActionScript
attribute. A malicious site could use this flaw to inject arbitrary
HTML content, confusing the user running the browser. (CVE-2008-4823)

A flaw was found in the way Flash Player interprets policy files. It
was possible to bypass a non-root domain policy, possibly allowing a
malicious site to access data in a different domain. (CVE-2008-4822)

A flaw was found in how Flash Player's jar: protocol handler interacts
with Mozilla. A malicious flash application could use this flaw to
disclose sensitive information. (CVE-2008-4821)

Updated Flash Player also extends mechanisms to help prevent an
attacker from executing a DNS rebinding attack. (CVE-2008-4819)

All users of Adobe Flash Player should upgrade to this updated
package, which contains Flash Player version 9.0.151.0."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-4324.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-6243.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-3873.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-4401.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-4503.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-4818.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-4819.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-4821.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-4822.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-4823.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-4824.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-5361.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-5362.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-5363.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb08-18.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb08-20.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb08-22.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/products/flashplayer/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0980.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected flash-plugin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 79, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:flash-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.7");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL3", cpu:"i386", reference:"flash-plugin-9.0.151.0-1.el3.with.oss")) flag++;

if (rpm_check(release:"RHEL4", cpu:"i386", reference:"flash-plugin-9.0.151.0-1.el4")) flag++;

if (rpm_check(release:"RHEL4", sp:"7", cpu:"i386", reference:"flash-plugin-9.0.151.0-1.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
