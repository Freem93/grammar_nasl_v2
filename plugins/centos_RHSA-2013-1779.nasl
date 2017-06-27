#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1779 and 
# CentOS Errata and Security Advisory 2013:1779 respectively.
#

include("compat.inc");

if (description)
{
  script_id(71179);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/05/19 23:52:01 $");

  script_cve_id("CVE-2013-4566");
  script_bugtraq_id(64114);
  script_osvdb_id(100516);
  script_xref(name:"RHSA", value:"2013:1779");

  script_name(english:"CentOS 5 / 6 : mod_nss (CESA-2013:1779)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated mod_nss package that fixes one security issue is now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The mod_nss module provides strong cryptography for the Apache HTTP
Server via the Secure Sockets Layer (SSL) and Transport Layer Security
(TLS) protocols, using the Network Security Services (NSS) security
library.

A flaw was found in the way mod_nss handled the NSSVerifyClient
setting for the per-directory context. When configured to not require
a client certificate for the initial connection and only require it
for a specific directory, mod_nss failed to enforce this requirement
and allowed a client to access the directory when no valid client
certificate was provided. (CVE-2013-4566)

Red Hat would like to thank Albert Smith of OUSD(AT&L) for reporting
this issue.

All mod_nss users should upgrade to this updated package, which
contains a backported patch to correct this issue. The httpd service
must be restarted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-December/020033.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d76705d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-December/020039.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2710b3b0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mod_nss package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_nss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"mod_nss-1.0.8-8.el5_10")) flag++;

if (rpm_check(release:"CentOS-6", reference:"mod_nss-1.0.8-19.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
