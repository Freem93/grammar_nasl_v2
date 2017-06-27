#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2393 and 
# CentOS Errata and Security Advisory 2015:2393 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(87156);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/11/17 21:12:10 $");

  script_cve_id("CVE-2014-8710", "CVE-2014-8711", "CVE-2014-8712", "CVE-2014-8713", "CVE-2014-8714", "CVE-2015-0562", "CVE-2015-0563", "CVE-2015-0564", "CVE-2015-2188", "CVE-2015-2189", "CVE-2015-2191", "CVE-2015-3182", "CVE-2015-3810", "CVE-2015-3811", "CVE-2015-3812", "CVE-2015-3813", "CVE-2015-6243", "CVE-2015-6244", "CVE-2015-6245", "CVE-2015-6246", "CVE-2015-6248");
  script_osvdb_id(114572, 114573, 114574, 114579, 114580, 116811, 116812, 116813, 119256, 119257, 119259, 122054, 122089, 122090, 122091, 126174, 126175, 126176, 126177, 126179);
  script_xref(name:"RHSA", value:"2015:2393");

  script_name(english:"CentOS 7 : wireshark (CESA-2015:2393)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated wireshark packages that fix multiple security issues, several
bugs, and add various enhancements are now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The wireshark packages contain a network protocol analyzer used to
capture and browse the traffic running on a computer network.

Several denial of service flaws were found in Wireshark. Wireshark
could crash or stop responding if it read a malformed packet off a
network, or opened a malicious dump file. (CVE-2015-2188,
CVE-2015-2189, CVE-2015-2191, CVE-2015-3810, CVE-2015-3811,
CVE-2015-3812, CVE-2015-3813, CVE-2014-8710, CVE-2014-8711,
CVE-2014-8712, CVE-2014-8713, CVE-2014-8714, CVE-2015-0562,
CVE-2015-0563, CVE-2015-0564, CVE-2015-3182, CVE-2015-6243,
CVE-2015-6244, CVE-2015-6245, CVE-2015-6246, CVE-2015-6248)

The CVE-2015-3182 issue was discovered by Martin Zember of Red Hat.

The wireshark packages have been upgraded to upstream version 1.10.14,
which provides a number of bug fixes and enhancements over the
previous version. (BZ#1238676)

This update also fixes the following bug :

* Prior to this update, when using the tshark utility to capture
packets over the interface, tshark failed to create output files in
the .pcap format even if it was specified using the '-F' option. This
bug has been fixed, the '-F' option is now honored, and the result
saved in the .pcap format as expected. (BZ#1227199)

In addition, this update adds the following enhancement :

* Previously, wireshark included only microseconds in the .pcapng
format. With this update, wireshark supports nanosecond time stamp
precision to allow for more accurate time stamps. (BZ#1213339)

All wireshark users are advised to upgrade to these updated packages,
which correct these issues and add these enhancements. All running
instances of Wireshark must be restarted for the update to take
effect."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-November/002675.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d8b6fd1c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"wireshark-1.10.14-7.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"wireshark-devel-1.10.14-7.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"wireshark-gnome-1.10.14-7.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
