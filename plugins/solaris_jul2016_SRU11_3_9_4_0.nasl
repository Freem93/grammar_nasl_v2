#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for jul2016.
#
include("compat.inc");

if (description)
{
  script_id(92455);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/10/25 16:58:36 $");

  script_cve_id("CVE-2016-5452", "CVE-2016-5454", "CVE-2016-5471");

  script_name(english:"Oracle Solaris Critical Patch Update : jul2016_SRU11_3_9_4_0");
  script_summary(english:"Check for the jul2016 CPU");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch from CPU
jul2016."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This Solaris system is missing necessary patches to address critical
security updates :

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Verified Boot).
    The supported version that is affected is 11.3. Easily
    exploitable vulnerability allows low privileged attacker
    with logon to the infrastructure where Solaris executes
    to compromise Solaris. Successful attacks of this
    vulnerability can result in unauthorized access to
    critical data or complete access to all Solaris
    accessible data. (CVE-2016-5452)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Verified Boot).
    The supported version that is affected is 11.3.
    Difficult to exploit vulnerability allows low privileged
    attacker with logon to the infrastructure where Solaris
    executes to compromise Solaris. While the vulnerability
    is in Solaris, attacks may significantly impact
    additional products. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of Solaris as well as unauthorized update, insert
    or delete access to some of Solaris accessible data.
    (CVE-2016-5454)

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Kernel). The
    supported version that is affected is 11.3. Easily
    exploitable vulnerability allows low privileged attacker
    with logon to the infrastructure where Solaris executes
    to compromise Solaris. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of Solaris. (CVE-2016-5471)"
  );
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3089849.xml
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42cde00c"
  );
  # http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?453b5f8c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.oracle.com/rs?type=doc&id=2157475.1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the jul2016 CPU from the Oracle support website."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:N/I:L/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/20");
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


fix_release = "0.5.11-0.175.3.9.0.4.0";

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.3.9.0.4.0", sru:"11.3.9.4.0") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report2());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
