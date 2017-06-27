#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0473 and 
# Oracle Linux Security Advisory ELSA-2011-0473 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68263);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/12/01 16:57:59 $");

  script_cve_id("CVE-2011-0072", "CVE-2011-0073", "CVE-2011-0074", "CVE-2011-0075", "CVE-2011-0077", "CVE-2011-0078", "CVE-2011-0080");
  script_xref(name:"RHSA", value:"2011:0473");

  script_name(english:"Oracle Linux 4 : seamonkey (ELSA-2011-0473)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:0473 :

Updated SeaMonkey packages that fix several security issues are now
available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

SeaMonkey is an open source web browser, email and newsgroup client,
IRC chat client, and HTML editor.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could possibly lead to arbitrary
code execution with the privileges of the user running SeaMonkey.
(CVE-2011-0080)

An arbitrary memory write flaw was found in the way SeaMonkey handled
out-of-memory conditions. If all memory was consumed when a user
visited a malicious web page, it could possibly lead to arbitrary code
execution with the privileges of the user running SeaMonkey.
(CVE-2011-0078)

An integer overflow flaw was found in the way SeaMonkey handled the
HTML frameset tag. A web page with a frameset tag containing large
values for the 'rows' and 'cols' attributes could trigger this flaw,
possibly leading to arbitrary code execution with the privileges of
the user running SeaMonkey. (CVE-2011-0077)

A flaw was found in the way SeaMonkey handled the HTML iframe tag. A
web page with an iframe tag containing a specially crafted source
address could trigger this flaw, possibly leading to arbitrary code
execution with the privileges of the user running SeaMonkey.
(CVE-2011-0075)

A flaw was found in the way SeaMonkey displayed multiple marquee
elements. A malformed HTML document could cause SeaMonkey to execute
arbitrary code with the privileges of the user running SeaMonkey.
(CVE-2011-0074)

A flaw was found in the way SeaMonkey handled the nsTreeSelection
element. Malformed content could cause SeaMonkey to execute arbitrary
code with the privileges of the user running SeaMonkey.
(CVE-2011-0073)

A use-after-free flaw was found in the way SeaMonkey appended frame
and iframe elements to a DOM tree when the NoScript add-on was
enabled. Malicious HTML content could cause SeaMonkey to execute
arbitrary code with the privileges of the user running SeaMonkey.
(CVE-2011-0072)

All SeaMonkey users should upgrade to these updated packages, which
correct these issues. After installing the update, SeaMonkey must be
restarted for the changes to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-April/002108.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Firefox "nsTreeRange" Dangling Pointer Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-chat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-mail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"seamonkey-1.0.9-70.0.1.el4_8")) flag++;
if (rpm_check(release:"EL4", reference:"seamonkey-chat-1.0.9-70.0.1.el4_8")) flag++;
if (rpm_check(release:"EL4", reference:"seamonkey-devel-1.0.9-70.0.1.el4_8")) flag++;
if (rpm_check(release:"EL4", reference:"seamonkey-dom-inspector-1.0.9-70.0.1.el4_8")) flag++;
if (rpm_check(release:"EL4", reference:"seamonkey-js-debugger-1.0.9-70.0.1.el4_8")) flag++;
if (rpm_check(release:"EL4", reference:"seamonkey-mail-1.0.9-70.0.1.el4_8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "seamonkey / seamonkey-chat / seamonkey-devel / etc");
}
