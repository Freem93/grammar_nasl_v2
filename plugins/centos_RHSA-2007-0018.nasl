#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0018 and 
# CentOS Errata and Security Advisory 2007:0018 respectively.
#

include("compat.inc");

if (description)
{
  script_id(24286);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/05/19 23:25:26 $");

  script_cve_id("CVE-2005-4348", "CVE-2006-5867");
  script_bugtraq_id(15987, 21903);
  script_osvdb_id(21906, 31580);
  script_xref(name:"RHSA", value:"2007:0018");

  script_name(english:"CentOS 3 / 4 : fetchmail (CESA-2007:0018)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated fetchmail packages that fix two security issues are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Fetchmail is a remote mail retrieval and forwarding utility.

A denial of service flaw was found when Fetchmail was run in multidrop
mode. A malicious mail server could send a message without headers
which would cause Fetchmail to crash (CVE-2005-4348). This issue did
not affect the version of Fetchmail shipped with Red Hat Enterprise
Linux 2.1 or 3.

A flaw was found in the way Fetchmail used TLS encryption to connect
to remote hosts. Fetchmail provided no way to enforce the use of TLS
encryption and would not authenticate POP3 protocol connections
properly (CVE-2006-5867). This update corrects this issue by enforcing
TLS encryption when the 'sslproto' configuration directive is set to
'tls1'.

Users of Fetchmail should update to these packages, which contain
backported patches to correct these issues.

Note: This update may break configurations which assumed that
Fetchmail would use plain-text authentication if TLS encryption is not
supported by the POP3 server even if the 'sslproto' directive is set
to 'tls1'. If you are using a custom configuration that depended on
this behavior you will need to modify your configuration appropriately
after installing this update."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-February/013498.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ffb09bb3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-February/013499.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5436bf2c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-January/013489.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd72f603"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-January/013490.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8dcc07a2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-January/013491.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?871af1c5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-January/013493.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a032663d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected fetchmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fetchmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/09");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"fetchmail-6.2.0-3.el3.3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"fetchmail-6.2.5-6.el4.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
