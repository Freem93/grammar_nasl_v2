#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0341 and 
# CentOS Errata and Security Advisory 2014:0341 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(73276);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/04/28 18:05:38 $");

  script_cve_id("CVE-2012-6056", "CVE-2012-6060", "CVE-2012-6061", "CVE-2012-6062", "CVE-2013-3557", "CVE-2013-3559", "CVE-2013-4081", "CVE-2013-4083", "CVE-2013-4927", "CVE-2013-4931", "CVE-2013-4932", "CVE-2013-4933", "CVE-2013-4934", "CVE-2013-4935", "CVE-2013-5721", "CVE-2013-7112", "CVE-2014-2281", "CVE-2014-2299");
  script_bugtraq_id(56729, 59995, 60021, 60504, 60505, 61471, 62320, 62868, 64411, 66066, 66068);
  script_osvdb_id(97220);
  script_xref(name:"RHSA", value:"2014:0341");

  script_name(english:"CentOS 5 : wireshark (CESA-2014:0341)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated wireshark packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Wireshark is a network protocol analyzer. It is used to capture and
browse the traffic running on a computer network.

Multiple flaws were found in Wireshark. If Wireshark read a malformed
packet off a network or opened a malicious dump file, it could crash
or, possibly, execute arbitrary code as the user running Wireshark.
(CVE-2013-3559, CVE-2013-4083, CVE-2014-2281, CVE-2014-2299)

Several denial of service flaws were found in Wireshark. Wireshark
could crash or stop responding if it read a malformed packet off a
network, or opened a malicious dump file. (CVE-2012-5595,
CVE-2012-5598, CVE-2012-5599, CVE-2012-5600, CVE-2012-6056,
CVE-2012-6060, CVE-2012-6061, CVE-2012-6062, CVE-2013-3557,
CVE-2013-4081, CVE-2013-4927, CVE-2013-4931, CVE-2013-4932,
CVE-2013-4933, CVE-2013-4934, CVE-2013-4935, CVE-2013-5721,
CVE-2013-7112)

All Wireshark users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. All running
instances of Wireshark must be restarted for the update to take
effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-March/020237.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f6f2674"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Wireshark wiretap/mpeg.c Stack Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"wireshark-1.0.15-6.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"wireshark-gnome-1.0.15-6.el5_10")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
