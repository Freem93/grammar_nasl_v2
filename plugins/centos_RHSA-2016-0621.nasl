#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0621 and 
# CentOS Errata and Security Advisory 2016:0621 respectively.
#

include("compat.inc");

if (description)
{
  script_id(90452);
  script_version("$Revision: 2.13 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2016-2110", "CVE-2016-2111", "CVE-2016-2118");
  script_osvdb_id(136339, 136990, 136991);
  script_xref(name:"RHSA", value:"2016:0621");

  script_name(english:"CentOS 5 : samba (CESA-2016:0621) (Badlock)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for samba is now available for Red Hat Enterprise Linux 5.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

[Updated 14 April 2016] This advisory previously incorrectly listed
the CVE-2016-2112 issue as addressed by this update. However, this
issue did not affect the samba packages on Red Hat Enterprise Linux 5.
The CVE-2016-2115 was also incorrectly listed as addressed by this
update. This issue does affect the samba packages on Red Hat
Enterprise Linux 5. Customers are advised to use the 'client signing =
required' configuration option in the smb.conf file to mitigate
CVE-2016-2115. No changes have been made to the packages.

Samba is an open source implementation of the Server Message Block
(SMB) protocol and the related Common Internet File System (CIFS)
protocol, which allow PC-compatible machines to share files, printers,
and various information.

Security Fix(es) :

* A protocol flaw, publicly referred to as Badlock, was found in the
Security Account Manager Remote Protocol (MS-SAMR) and the Local
Security Authority (Domain Policy) Remote Protocol (MS-LSAD). Any
authenticated DCE/RPC connection that a client initiates against a
server could be used by a man-in-the-middle attacker to impersonate
the authenticated user against the SAMR or LSA service on the server.
As a result, the attacker would be able to get read/write access to
the Security Account Manager database, and use this to reveal all
passwords or any other potentially sensitive information in that
database. (CVE-2016-2118)

* Several flaws were found in Samba's implementation of NTLMSSP
authentication. An unauthenticated, man-in-the-middle attacker could
use this flaw to clear the encryption and integrity flags of a
connection, causing data to be transmitted in plain text. The attacker
could also force the client or server into sending data in plain text
even if encryption was explicitly requested for that connection.
(CVE-2016-2110)

* It was discovered that Samba configured as a Domain Controller would
establish a secure communication channel with a machine using a
spoofed computer name. A remote attacker able to observe network
traffic could use this flaw to obtain session-related information
about the spoofed machine. (CVE-2016-2111)

Red Hat would like to thank the Samba project for reporting these
issues. Upstream acknowledges Stefan Metzmacher (SerNet) as the
original reporter of CVE-2016-2118 and CVE-2016-2110."
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-April/021823.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?60e91a03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-swat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"libsmbclient-3.0.33-3.41.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libsmbclient-devel-3.0.33-3.41.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba-3.0.33-3.41.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba-client-3.0.33-3.41.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba-common-3.0.33-3.41.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba-swat-3.0.33-3.41.el5_11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
