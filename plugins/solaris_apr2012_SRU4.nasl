#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for apr2012.
#
include("compat.inc");

if (description)
{
  script_id(76801);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/11/13 15:27:57 $");

  script_cve_id("CVE-2012-1683", "CVE-2012-1691", "CVE-2012-1698");
  script_bugtraq_id(53128, 53130, 53137);
  script_osvdb_id(81225, 81226, 81227, 81228, 81229, 81230, 81231, 81232, 81233, 81234, 81235, 81236, 81237, 81250, 81395, 81396, 81398, 81399, 81400, 81401, 81402, 81403, 81404, 81405, 81408, 81409, 81440, 81545, 81546);

  script_name(english:"Oracle Solaris Critical Patch Update : apr2012_SRU4");
  script_summary(english:"Check for the apr2012 CPU");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch from CPU
apr2012."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This Solaris system is missing necessary patches to address critical
security updates :

  - Vulnerability in the Solaris component of Oracle Sun
    Products Suite (subcomponent: gssd(1M)). Supported
    versions that are affected are 8, 9, 10 and 11. Very
    difficult to exploit vulnerability requiring logon to
    Operating System plus additional, multiple logins to
    components. Successful attack of this vulnerability can
    escalate attacker privileges resulting in unauthorized
    Operating System takeover including arbitrary code
    execution. (CVE-2012-1683)

  - Vulnerability in the Solaris component of Oracle Sun
    Products Suite (subcomponent: Kernel/Privileges). The
    supported version that is affected is 11. Difficult to
    exploit vulnerability requiring logon to Operating
    System plus additional login/authentication to component
    or subcomponent. Successful attack of this vulnerability
    can escalate attacker privileges resulting in
    unauthorized Operating System takeover including
    arbitrary code execution. (CVE-2012-1691)

  - Vulnerability in the Solaris component of Oracle Sun
    Products Suite (subcomponent: Kernel/GLD(7D)). The
    supported version that is affected is 11. Very difficult
    to exploit vulnerability allows successful authenticated
    network attacks via TCP/IP. Successful attack of this
    vulnerability can result in unauthorized read access to
    a subset of Solaris accessible data. (CVE-2012-1698)"
  );
  # http://support.oracle.com/CSP/main/article?cmd=show&type=NOT&id=1446032.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75401354"
  );
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/1690959.xml
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?289b1163"
  );
  # http://www.oracle.com/technetwork/topics/security/cpuapr2012-366314.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9865fa8a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the apr2012 CPU from the Oracle support website."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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


fix_release = "0.5.11-0.175.0.4.0.5.0";

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.0.4.0.5.0", sru:"11/11 SRU 4") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report2());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
