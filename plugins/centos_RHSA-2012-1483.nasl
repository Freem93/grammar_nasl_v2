#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1483 and 
# CentOS Errata and Security Advisory 2012:1483 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(63006);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/04 14:39:51 $");

  script_cve_id("CVE-2012-4201", "CVE-2012-4202", "CVE-2012-4207", "CVE-2012-4209", "CVE-2012-4214", "CVE-2012-4215", "CVE-2012-4216", "CVE-2012-5829", "CVE-2012-5830", "CVE-2012-5833", "CVE-2012-5835", "CVE-2012-5839", "CVE-2012-5840", "CVE-2012-5841", "CVE-2012-5842");
  script_bugtraq_id(56607, 56628, 56633);
  script_osvdb_id(87581, 87582, 87583, 87585, 87587, 87588, 87594, 87595, 87596, 87598, 87601, 87606, 87607, 87608, 87609);
  script_xref(name:"RHSA", value:"2012:1483");

  script_name(english:"CentOS 5 / 6 : thunderbird (CESA-2012:1483)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated thunderbird package that fixes several security issues is
now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the processing of malformed content.
Malicious content could cause Thunderbird to crash or, potentially,
execute arbitrary code with the privileges of the user running
Thunderbird. (CVE-2012-4214, CVE-2012-4215, CVE-2012-4216,
CVE-2012-5829, CVE-2012-5830, CVE-2012-5833, CVE-2012-5835,
CVE-2012-5839, CVE-2012-5840, CVE-2012-5842)

A buffer overflow flaw was found in the way Thunderbird handled GIF
(Graphics Interchange Format) images. Content containing a malicious
GIF image could cause Thunderbird to crash or, possibly, execute
arbitrary code with the privileges of the user running Thunderbird.
(CVE-2012-4202)

A flaw was found in the way Thunderbird decoded the HZ-GB-2312
character encoding. Malicious content could cause Thunderbird to run
JavaScript code with the permissions of different content.
(CVE-2012-4207)

A flaw was found in the location object implementation in Thunderbird.
Malicious content could possibly use this flaw to allow restricted
content to be loaded by plug-ins. (CVE-2012-4209)

A flaw was found in the way cross-origin wrappers were implemented.
Malicious content could use this flaw to perform cross-site scripting
attacks. (CVE-2012-5841)

A flaw was found in the evalInSandbox implementation in Thunderbird.
Malicious content could use this flaw to perform cross-site scripting
attacks. (CVE-2012-4201)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Abhishek Arya, miaubiz, Jesse Ruderman,
Andrew McCreight, Bob Clary, Kyle Huey, Atte Kettunen, Masato
Kinugawa, Mariusz Mlynski, Bobby Holley, and moz_bug_r_a4 as the
original reporters of these issues.

Note: All issues except CVE-2012-4202 cannot be exploited by a
specially crafted HTML mail message as JavaScript is disabled by
default for mail messages. They could be exploited another way in
Thunderbird, for example, when viewing the full remote content of an
RSS feed.

All Thunderbird users should upgrade to this updated package, which
contains Thunderbird version 10.0.11 ESR, which corrects these issues.
After installing the update, Thunderbird must be restarted for the
changes to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-November/019004.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?58c4572b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-November/019009.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97fbd26f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"thunderbird-10.0.11-1.el5.centos")) flag++;

if (rpm_check(release:"CentOS-6", reference:"thunderbird-10.0.11-1.el6.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
