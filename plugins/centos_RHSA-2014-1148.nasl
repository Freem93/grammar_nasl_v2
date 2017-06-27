#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1148 and 
# CentOS Errata and Security Advisory 2014:1148 respectively.
#

include("compat.inc");

if (description)
{
  script_id(77509);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/08/15 14:21:28 $");

  script_cve_id("CVE-2013-4115", "CVE-2014-3609");
  script_bugtraq_id(61111, 69453);
  script_osvdb_id(95165);
  script_xref(name:"RHSA", value:"2014:1148");

  script_name(english:"CentOS 5 / 6 : squid (CESA-2014:1148)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated squid package that fixes two security issues is now
available for Red Hat Enterprise Linux 5 and 6.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Squid is a high-performance proxy caching server for web clients,
supporting FTP, Gopher, and HTTP data objects.

A flaw was found in the way Squid handled malformed HTTP Range
headers. A remote attacker able to send HTTP requests to the Squid
proxy could use this flaw to crash Squid. (CVE-2014-3609)

A buffer overflow flaw was found in Squid's DNS lookup module. A
remote attacker able to send HTTP requests to the Squid proxy could
use this flaw to crash Squid. (CVE-2013-4115)

Red Hat would like to thank the Squid project for reporting the
CVE-2014-3609 issue. Upstream acknowledges Matthew Daley as the
original reporter.

All Squid users are advised to upgrade to this updated package, which
contains backported patches to correct these issues. After installing
this update, the squid service will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-September/020534.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e174bdf5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-September/020537.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3971ce6c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected squid package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/04");
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
if (rpm_check(release:"CentOS-5", reference:"squid-2.6.STABLE21-7.el5_10")) flag++;

if (rpm_check(release:"CentOS-6", reference:"squid-3.1.10-22.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
