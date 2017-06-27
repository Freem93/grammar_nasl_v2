#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for jan2017.
#
include("compat.inc");

if (description)
{
  script_id(96601);
  script_version("$Revision: 3.8 $");
  script_cvs_date("$Date: 2017/04/21 16:53:28 $");

  script_cve_id("CVE-2016-8330", "CVE-2017-3276");
  script_bugtraq_id(95544, 95572);

  script_name(english:"Oracle Solaris Critical Patch Update : jan2017_SRU11_3_15_4_0");
  script_summary(english:"Check for the jan2017 CPU");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch from CPU
jan2017."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This Solaris system is missing necessary patches to address critical
security updates :

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Kernel). The
    supported version that is affected is 11.3. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise
    Solaris. Successful attacks of this vulnerability can
    result in unauthorized update, insert or delete access
    to some of Solaris accessible data. (CVE-2016-8330)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Kernel Zones
    virtualized block driver). The supported version that is
    affected is 11.3. Difficult to exploit vulnerability
    allows high privileged attacker with logon to the
    infrastructure where Solaris executes to compromise
    Solaris. Successful attacks of this vulnerability can
    result in unauthorized creation, deletion or
    modification access to critical data or all Solaris
    accessible data and unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of
    Solaris. (CVE-2017-3276)"
  );
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3432537.xml
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7983a43f"
  );
  # http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?89a8e429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.oracle.com/rs?type=doc&id=2220066.1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the jan2017 CPU from the Oracle support website."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris11/release");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Solaris11/release");
if (isnull(release)) audit(AUDIT_OS_NOT, "Solaris11");


fix_release = "0.5.11-0.175.3.15.0.4.0";

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.3.15.0.4.0", sru:"11.3.15.4.0") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report2());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
