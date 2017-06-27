#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for jul2015.
#
include("compat.inc");

if (description)
{
  script_id(84760);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2015/11/13 15:27:58 $");

  script_cve_id("CVE-2015-2589", "CVE-2015-2651", "CVE-2015-4770");
  script_osvdb_id(124697, 124698, 124699, 124700, 124701, 124702, 124703, 124704, 124705, 124718);

  script_name(english:"Oracle Solaris Critical Patch Update : jul2015_SRU11_2_11_5_0");
  script_summary(english:"Check for the jul2015 CPU");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch from CPU
jul2015."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This Solaris system is missing necessary patches to address critical
security updates :

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: S10 Branded Zone).
    Supported versions that are affected are 10 and 11.2.
    Easily exploitable vulnerability requiring logon to
    Operating System. Successful attack of this
    vulnerability can result in unauthorized Operating
    System hang or frequently repeatable crash (complete
    DOS). (CVE-2015-2589)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Kernel Zones
    virtualized NIC driver). The supported version that is
    affected is 11.2. Very difficult to exploit
    vulnerability requiring logon to Operating System plus
    additional login/authentication to component or
    subcomponent. Successful attack of this vulnerability
    can escalate attacker privileges resulting in
    unauthorized Operating System hang or frequently
    repeatable crash (complete DOS). (CVE-2015-2651)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: UNIX filesystem).
    Supported versions that are affected are 10 and 11.2.
    Easily exploitable vulnerability requiring logon to
    Operating System. Successful attack of this
    vulnerability can result in unauthorized Operating
    System hang or frequently repeatable crash (complete
    DOS). (CVE-2015-4770)"
  );
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/2368792.xml
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?591ab328"
  );
  # http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d18c2a85"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.oracle.com/rs?type=doc&id=20018633.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.oracle.com/rs?type=doc&id=2018633.1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the jul2015 CPU from the Oracle support website."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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


fix_release = "0.5.11-0.175.2.11.0.5.0";

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.2.11.0.5.0", sru:"11.2.11.5.0") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report2());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
