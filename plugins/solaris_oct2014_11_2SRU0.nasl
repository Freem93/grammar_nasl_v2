#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for oct2014.
#
include("compat.inc");

if (description)
{
  script_id(78462);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/11/13 15:27:58 $");

  script_cve_id("CVE-2014-4275", "CVE-2014-4276", "CVE-2014-4277", "CVE-2014-4280", "CVE-2014-4282", "CVE-2014-4283", "CVE-2014-4284", "CVE-2014-6470", "CVE-2014-6473", "CVE-2014-6490", "CVE-2014-6497", "CVE-2014-6501", "CVE-2014-6529");
  script_bugtraq_id(70503, 70509, 70513, 70520, 70539, 70543, 70546, 70551, 70557, 70559, 70561, 70563);
  script_osvdb_id(107729, 113340, 113341, 113342, 113343, 113344, 113345, 113346, 113347, 113348, 113349, 113350, 113353, 113354);

  script_name(english:"Oracle Solaris Critical Patch Update : oct2014_11_2SRU0");
  script_summary(english:"Check for the oct2014 CPU");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch from CPU
oct2014."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This Solaris system is missing necessary patches to address critical
security updates :

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: SMB server kernel
    module). The supported version that is affected is 11.
    Easily exploitable vulnerability requiring logon to
    Operating System. Successful attack of this
    vulnerability can result in unauthorized Operating
    System hang or frequently repeatable crash (complete
    DOS). (CVE-2014-4275)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Common Internet
    File System(CIFS)). The supported version that is
    affected is 11. Easily exploitable vulnerability allows
    successful unauthenticated network attacks via CIFS.
    Successful attack of this vulnerability can result in
    unauthorized update, insert or delete access to some
    Solaris accessible data as well as read access to a
    subset of Solaris accessible data and ability to cause a
    partial denial of service (partial DOS) of Solaris.
    (CVE-2014-4276)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Automated Install
    Engine). The supported version that is affected is 11.
    Easily exploitable vulnerability allows successful
    unauthenticated network attacks via HTTP. Successful
    attack of this vulnerability can result in unauthorized
    read access to a subset of Solaris accessible data.
    (CVE-2014-4277)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: IPS transfer
    module). The supported version that is affected is 11.
    Easily exploitable vulnerability requiring logon to
    Operating System. Successful attack of this
    vulnerability can result in unauthorized update, insert
    or delete access to some Solaris accessible data as well
    as read access to a subset of Solaris accessible data
    and ability to cause a partial denial of service
    (partial DOS) of Solaris. (CVE-2014-4280)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Automated Install
    Engine). The supported version that is affected is 11.
    Difficult to exploit vulnerability allows successful
    unauthenticated network attacks via SSL/TLS. Successful
    attack of this vulnerability can result in unauthorized
    read access to a subset of Solaris accessible data.
    (CVE-2014-4283)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Kernel/X86). The
    supported version that is affected is 11. Easily
    exploitable vulnerability requiring logon to Operating
    System. Successful attack of this vulnerability can
    result in unauthorized Operating System takeover
    including arbitrary code execution. (CVE-2014-4282)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: IPS transfer
    module). The supported version that is affected is 11.
    Difficult to exploit vulnerability requiring logon to
    Operating System. Successful attack of this
    vulnerability can result in unauthorized update, insert
    or delete access to some Solaris accessible data as well
    as read access to a subset of Solaris accessible data
    and ability to cause a partial denial of service
    (partial DOS) of Solaris. (CVE-2014-4284)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Archive Utility).
    The supported version that is affected is 11. Easily
    exploitable vulnerability requiring logon to Operating
    System plus additional login/authentication to component
    or subcomponent. Successful attack of this vulnerability
    can escalate attacker privileges resulting in
    unauthorized Operating System takeover including
    arbitrary code execution. (CVE-2014-6470)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Zone Framework).
    Supported versions that are affected are 10 and 11.
    Easily exploitable vulnerability requiring logon to
    Operating System. Successful attack of this
    vulnerability can result in unauthorized Operating
    System takeover including arbitrary code execution.
    Note: For Solaris 10, it only applies to SPARC systems
    with Solaris 8 and Solaris 9 branded zones.
    (CVE-2014-6473)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: SMB server user
    component). The supported version that is affected is
    11. Easily exploitable vulnerability allows successful
    unauthenticated network attacks via SMB. Successful
    attack of this vulnerability can result in unauthorized
    ability to cause a partial denial of service (partial
    DOS) of Solaris. (CVE-2014-6490)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Kernel). The
    supported version that is affected is 11. Easily
    exploitable vulnerability requiring logon to Operating
    System. Successful attack of this vulnerability can
    result in unauthorized Operating System hang or
    frequently repeatable crash (complete DOS).
    (CVE-2014-6497)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: SSH). The
    supported version that is affected is 11. Easily
    exploitable vulnerability requiring logon to Operating
    System. Successful attack of this vulnerability can
    result in unauthorized read access to a subset of
    Solaris accessible data. (CVE-2014-6501)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Hermon HCA PCIe
    driver). The supported version that is affected is 11.
    Very difficult to exploit vulnerability allows
    successful unauthenticated network attacks via None, but
    can only be launched from an adjacent network.
    Successful attack of this vulnerability can result in
    unauthorized Operating System takeover including
    arbitrary code execution. (CVE-2014-6529)"
  );
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/2292506.xml
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3485133e"
  );
  # http://www.oracle.com/technetwork/topics/security/cpuoct2014-1972960.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6dcc7b47"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.oracle.com/rs?type=doc&id=1931712.1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the oct2014 CPU from the Oracle support website."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/15");
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


fix_release = "0.5.11-0.175.2.0.0.0.0";

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.2.0.0.0.0", sru:"S11.2") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report2());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
