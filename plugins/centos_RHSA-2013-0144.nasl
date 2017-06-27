#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0144 and 
# CentOS Errata and Security Advisory 2013:0144 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(63431);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/04 14:39:52 $");

  script_cve_id("CVE-2013-0744", "CVE-2013-0746", "CVE-2013-0748", "CVE-2013-0750", "CVE-2013-0753", "CVE-2013-0754", "CVE-2013-0758", "CVE-2013-0759", "CVE-2013-0762", "CVE-2013-0766", "CVE-2013-0767", "CVE-2013-0769");
  script_bugtraq_id(57185);
  script_osvdb_id(88997, 89001, 89002, 89003, 89009, 89010, 89014, 89016, 89017, 89020, 89021, 89022);
  script_xref(name:"RHSA", value:"2013:0144");

  script_name(english:"CentOS 5 / 6 : firefox / xulrunner (CESA-2013:0144)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix several security issues are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2013-0744, CVE-2013-0746, CVE-2013-0750,
CVE-2013-0753, CVE-2013-0754, CVE-2013-0762, CVE-2013-0766,
CVE-2013-0767, CVE-2013-0769)

A flaw was found in the way Chrome Object Wrappers were implemented.
Malicious content could be used to cause Firefox to execute arbitrary
code via plug-ins installed in Firefox. (CVE-2013-0758)

A flaw in the way Firefox displayed URL values in the address bar
could allow a malicious site or user to perform a phishing attack.
(CVE-2013-0759)

An information disclosure flaw was found in the way certain JavaScript
functions were implemented in Firefox. An attacker could use this flaw
to bypass Address Space Layout Randomization (ASLR) and other security
restrictions. (CVE-2013-0748)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 10.0.12 ESR. You can find a link to
the Mozilla advisories in the References section of this erratum.

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Atte Kettunen, Boris Zbarsky, pa_kt,
regenrecht, Abhishek Arya, Christoph Diehl, Christian Holler, Mats
Palmgren, Chiaki Ishikawa, Mariusz Mlynski, Masato Kinugawa, and Jesse
Ruderman as the original reporters of these issues.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 10.0.12 ESR, which corrects these issues.
After installing the update, Firefox must be restarted for the changes
to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-January/019048.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?46b4792b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-January/019050.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?21bf9836"
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-January/019199.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d4394a18"
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-January/019200.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?31a50f0a"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-January/000461.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9c846111"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-January/000464.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?49b0226c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox and / or xulrunner packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 17.0.1 Flash Privileged Code Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/09");
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
if (rpm_check(release:"CentOS-5", reference:"firefox-10.0.12-1.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-10.0.12-1.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-10.0.12-1.el5_9")) flag++;

if (rpm_check(release:"CentOS-6", reference:"firefox-10.0.12-1.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xulrunner-10.0.12-1.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xulrunner-devel-10.0.12-1.el6.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
