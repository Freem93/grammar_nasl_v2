#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for apr2016.
#
include("compat.inc");

if (description)
{
  script_id(90622);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/21 14:22:37 $");

  script_cve_id("CVE-2016-3462", "CVE-2016-3465");

  script_name(english:"Oracle Solaris Critical Patch Update : apr2016_SRU11_3_7_5_0");
  script_summary(english:"Check for the apr2016 CPU");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch from CPU
apr2016."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This Solaris system is missing necessary patches to address critical
security updates :

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Network
    Configuration Service). The supported version that is
    affected is 11.3. Easily exploitable vulnerability
    allows low privileged attacker with logon to the
    infrastructure where Solaris executes to compromise
    Solaris. Successful attacks of this vulnerability can
    result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of Solaris.
    (CVE-2016-3462)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: ZFS). Supported
    versions that are affected are 10 and 11.3. Easily
    exploitable vulnerability allows low privileged attacker
    with logon to the infrastructure where Solaris executes
    to compromise Solaris. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of Solaris. (CVE-2016-3465)"
  );
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/2948264.xml
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2142a932"
  );
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?855180af"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.oracle.com/rs?type=doc&id=2123591.1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the apr2016 CPU from the Oracle support website."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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


fix_release = "0.5.11-0.175.3.7.0.5.0";

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.3.7.0.5.0", sru:"11.3.7.5.0") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report2());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
