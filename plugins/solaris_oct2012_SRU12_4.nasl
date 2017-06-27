#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for oct2012.
#
include("compat.inc");

if (description)
{
  script_id(76831);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/11/13 15:27:58 $");

  script_cve_id("CVE-2012-3165", "CVE-2012-3212", "CVE-2012-3215");
  script_bugtraq_id(56012, 56016, 56038);
  script_osvdb_id(86337, 86340, 86343);

  script_name(english:"Oracle Solaris Critical Patch Update : oct2012_SRU12_4");
  script_summary(english:"Check for the oct2012 CPU");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch from CPU
oct2012."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This Solaris system is missing necessary patches to address critical
security updates :

  - Vulnerability in the Solaris component of Oracle Sun
    Products Suite (subcomponent: Kernel). Supported
    versions that are affected are 10 and 11. Difficult to
    exploit vulnerability requiring logon to Operating
    System. Successful attack of this vulnerability can
    result in unauthorized Operating System hang or
    frequently repeatable crash (complete DOS). Note:
    CVE-2012-3212 affects only Solaris on SPARC T4 servers.
    (CVE-2012-3212)

  - Vulnerability in the Solaris component of Oracle Sun
    Products Suite (subcomponent: mailx(1)). Supported
    versions that are affected are 8, 9, 10 and 11. Easily
    exploitable vulnerability requiring logon to Operating
    System. Successful attack of this vulnerability can
    result in unauthorized update, insert or delete access
    to some Solaris accessible data as well as read access
    to a subset of Solaris accessible data. (CVE-2012-3165)

  - Vulnerability in the Solaris component of Oracle Sun
    Products Suite (subcomponent: Kernel). Supported
    versions that are affected are 10 and 11. Easily
    exploitable vulnerability requiring logon to Operating
    System plus additional login/authentication to component
    or subcomponent. Successful attack of this vulnerability
    can escalate attacker privileges resulting in
    unauthorized read access to a subset of Solaris
    accessible data. Note: CVE-2012-3209 and CVE-2012-3215
    only affects Solaris on the SPARC platform.
    (CVE-2012-3215)"
  );
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/1865039.xml
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd421d02"
  );
  # http://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1cef09be"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.oracle.com/rs?type=doc&id=1475188.1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the oct2012 CPU from the Oracle support website."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/16");
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


fix_release = "0.5.11-0.175.0.12.0.4.0";

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.0.12.0.4.0", sru:"11/11 SRU 12.4") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report2());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
