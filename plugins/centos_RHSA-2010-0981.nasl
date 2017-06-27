#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0981.
#

include("compat.inc");

if (description)
{
  script_id(51782);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/06/28 13:29:43 $");

  script_cve_id("CVE-2010-2997", "CVE-2010-4375", "CVE-2010-4378", "CVE-2010-4379", "CVE-2010-4382", "CVE-2010-4383", "CVE-2010-4384", "CVE-2010-4385", "CVE-2010-4386", "CVE-2010-4392");
  script_bugtraq_id(45327);
  script_xref(name:"RHSA", value:"2010:0981");

  script_name(english:"CentOS 4 : HelixPlayer removal (CESA-2010:0981)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Helix Player contains multiple security flaws and should no longer be
used. This update removes the HelixPlayer package from Red Hat
Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Helix Player is a media player.

Multiple security flaws were discovered in RealPlayer. Helix Player
and RealPlayer share a common source code base; therefore, some of the
flaws discovered in RealPlayer may also affect Helix Player. Some of
these flaws could, when opening, viewing, or playing a malicious media
file or stream, lead to arbitrary code execution with the privileges
of the user running Helix Player. (CVE-2010-2997, CVE-2010-4375,
CVE-2010-4378, CVE-2010-4379, CVE-2010-4382, CVE-2010-4383,
CVE-2010-4384, CVE-2010-4385, CVE-2010-4386, CVE-2010-4392)

The Red Hat Security Response Team is unable to properly determine the
impact or fix all of these issues in Helix Player, due to the source
code for RealPlayer being unavailable.

Due to the security concerns this update removes the HelixPlayer
package from Red Hat Enterprise Linux 4. Users wishing to continue to
use Helix Player should download it directly from
https://player.helixcommunity.org/"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-January/017237.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f5d5efc5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-January/017238.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af5cb45c"
  );
  script_set_attribute(attribute:"solution", value:"Remove the affected HelixPlayer package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:HelixPlayer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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


if (rpm_exists(rpm:"HelixPlayer", release:"CentOS-4")) security_hole(0);
else audit(AUDIT_HOST_NOT, "affected");
