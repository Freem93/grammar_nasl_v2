#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1350 and 
# CentOS Errata and Security Advisory 2012:1350 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(62484);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/12 13:22:38 $");

  script_cve_id("CVE-2012-1956", "CVE-2012-3982", "CVE-2012-3986", "CVE-2012-3988", "CVE-2012-3990", "CVE-2012-3991", "CVE-2012-3992", "CVE-2012-3993", "CVE-2012-3994", "CVE-2012-3995", "CVE-2012-4179", "CVE-2012-4180", "CVE-2012-4181", "CVE-2012-4182", "CVE-2012-4183", "CVE-2012-4184", "CVE-2012-4185", "CVE-2012-4186", "CVE-2012-4187", "CVE-2012-4188");
  script_bugtraq_id(55260, 55856);
  script_osvdb_id(84990, 86094, 86095, 86096, 86098, 86099, 86100, 86101, 86102, 86104, 86108, 86109, 86110, 86111, 86112, 86113, 86114, 86115, 86116, 86117);
  script_xref(name:"RHSA", value:"2012:1350");

  script_name(english:"CentOS 5 / 6 : firefox (CESA-2012:1350)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix several security issues and one bug
are now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2012-3982, CVE-2012-3988, CVE-2012-3990,
CVE-2012-3995, CVE-2012-4179, CVE-2012-4180, CVE-2012-4181,
CVE-2012-4182, CVE-2012-4183, CVE-2012-4185, CVE-2012-4186,
CVE-2012-4187, CVE-2012-4188)

Two flaws in Firefox could allow a malicious website to bypass
intended restrictions, possibly leading to information disclosure, or
Firefox executing arbitrary code. Note that the information disclosure
issue could possibly be combined with other flaws to achieve arbitrary
code execution. (CVE-2012-3986, CVE-2012-3991)

Multiple flaws were found in the location object implementation in
Firefox. Malicious content could be used to perform cross-site
scripting attacks, script injection, or spoofing attacks.
(CVE-2012-1956, CVE-2012-3992, CVE-2012-3994)

Two flaws were found in the way Chrome Object Wrappers were
implemented. Malicious content could be used to perform cross-site
scripting attacks or cause Firefox to execute arbitrary code.
(CVE-2012-3993, CVE-2012-4184)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 10.0.8 ESR. You can find a link to the
Mozilla advisories in the References section of this erratum.

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Christian Holler, Jesse Ruderman,
Soroush Dalili, miaubiz, Abhishek Arya, Atte Kettunen, Johnny
Stenback, Alice White, moz_bug_r_a4, and Mariusz Mlynski as the
original reporters of these issues.

This update also fixes the following bug :

* In certain environments, storing personal Firefox configuration
files (~/.mozilla/) on an NFS share, such as when your home directory
is on a NFS share, led to Firefox functioning incorrectly, for
example, navigation buttons not working as expected, and bookmarks not
saving. This update adds a new configuration option,
storage.nfs_filesystem, that can be used to resolve this issue.

If you experience this issue :

1) Start Firefox.

2) Type 'about:config' (without quotes) into the URL bar and press the
Enter key.

3) If prompted with 'This might void your warranty!', click the 'I'll
be careful, I promise!' button.

4) Right-click in the Preference Name list. In the menu that opens,
select New -> Boolean.

5) Type 'storage.nfs_filesystem' (without quotes) for the preference
name and then click the OK button.

6) Select 'true' for the boolean value and then press the OK button.
(BZ#809571, BZ#816234)

All Firefox users should upgrade to these updated packages, which
contain Firefox version 10.0.8 ESR, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-October/018928.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b86a2c73"
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-October/018930.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a020aae2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 5.0 - 15.0.1 __exposedProps__ XCS Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"firefox-10.0.8-1.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-10.0.8-1.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-10.0.8-1.el5_8")) flag++;

if (rpm_check(release:"CentOS-6", reference:"firefox-10.0.8-1.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xulrunner-10.0.8-1.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xulrunner-devel-10.0.8-1.el6.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
