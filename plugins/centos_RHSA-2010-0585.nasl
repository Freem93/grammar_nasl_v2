#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0585 and 
# CentOS Errata and Security Advisory 2010:0585 respectively.
#

include("compat.inc");

if (description)
{
  script_id(48219);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/05/19 23:43:07 $");

  script_cve_id("CVE-2010-2251");
  script_bugtraq_id(43728);
  script_xref(name:"RHSA", value:"2010:0585");

  script_name(english:"CentOS 5 : lftp (CESA-2010:0585)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated lftp package that fixes one security issue is now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

LFTP is a sophisticated file transfer program for the FTP and HTTP
protocols. Like Bash, it has job control and uses the Readline library
for input. It has bookmarks, built-in mirroring, and can transfer
several files in parallel. It is designed with reliability in mind.

It was discovered that lftp trusted the file name provided in the
Content-Disposition HTTP header. A malicious HTTP server could use
this flaw to write or overwrite files in the current working directory
of a victim running lftp, by sending a different file from what the
victim requested. (CVE-2010-2251)

To correct this flaw, the following changes were made to lftp: the
'xfer:clobber' option now defaults to 'no', causing lftp to not
overwrite existing files, and a new option, 'xfer:auto-rename', which
defaults to 'no', has been introduced to control whether lftp should
use server-suggested file names. Refer to the 'Settings' section of
the lftp(1) manual page for additional details on changing lftp
settings.

All lftp users should upgrade to this updated package, which contains
a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-August/016860.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ceaaa4eb"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-August/016861.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6da56a20"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected lftp package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:lftp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"lftp-3.7.11-4.el5_5.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
