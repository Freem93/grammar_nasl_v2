#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for apr2017.
#
include("compat.inc");

if (description)
{
  script_id(99458);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/05/05 13:47:08 $");

  script_cve_id("CVE-2017-3510", "CVE-2017-3516");
  script_osvdb_id(155846, 155847);
  script_xref(name:"IAVA", value:"2017-A-0119");

  script_name(english:"Oracle Solaris Critical Patch Update : apr2017_SRU11_3_18_6_0");
  script_summary(english:"Check for the apr2017 CPU");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch from CPU
apr2017."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This Solaris system is missing necessary patches to address critical
security updates :

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Kernel Zones
    virtualized NIC driver). The supported version that is
    affected is 11.3. Easily exploitable vulnerability
    allows low privileged attacker with network access via
    multiple protocols to compromise Solaris. While the
    vulnerability is in Solaris, attacks may significantly
    impact additional products. Successful attacks of this
    vulnerability can result in unauthorized creation,
    deletion or modification access to critical data or all
    Solaris accessible data. (CVE-2017-3510)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Kernel Zones
    virtualized NIC driver). The supported version that is
    affected is 11.3. Easily exploitable vulnerability
    allows low privileged attacker with network access via
    multiple protocols to compromise Solaris. While the
    vulnerability is in Solaris, attacks may significantly
    impact additional products. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of Solaris. (CVE-2017-3516)"
  );
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3681811.xml
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?08e1362c"
  );
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?623d2c22"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.oracle.com/rs?type=doc&id=2252071.1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the apr2017 CPU from the Oracle support website."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"stig_severity", value:"I");
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


fix_release = "0.5.11-0.175.3.18.0.6.0";

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.3.18.0.6.0", sru:"11.3.18.6.0") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report2());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
