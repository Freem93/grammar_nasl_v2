#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for july2013.
#
include("compat.inc");

if (description)
{
  script_id(76822);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/11/13 15:27:58 $");

  script_cve_id("CVE-2013-0398", "CVE-2013-3752", "CVE-2013-3799");
  script_bugtraq_id(61245, 61250, 61273);
  script_osvdb_id(95303, 95304, 95305, 95306, 95307, 95308, 95309, 95310, 95311, 95312, 95313, 95314, 95315, 95316, 95317, 95318);

  script_name(english:"Oracle Solaris Critical Patch Update : july2013_SRU0");
  script_summary(english:"Check for the july2013 CPU");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch from CPU
july2013."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This Solaris system is missing necessary patches to address critical
security updates :

  - Vulnerability in the Solaris component of Oracle and Sun
    Systems Products Suite (subcomponent: Utility/Remote
    Execution Server(in.rexecd)). Supported versions that
    are affected are 8, 9, 10 and 11. Easily exploitable
    vulnerability allows successful unauthenticated network
    attacks via TCP/IP. Successful attack of this
    vulnerability can result in unauthorized read access to
    a subset of Solaris accessible data. (CVE-2013-0398)

  - Vulnerability in the Solaris component of Oracle and Sun
    Systems Products Suite (subcomponent: Service Management
    Facility (SMF)). The supported version that is affected
    is 11. Difficult to exploit vulnerability allows
    successful unauthenticated network attacks via NDMP.
    Successful attack of this vulnerability can result in
    unauthorized update, insert or delete access to some
    Solaris accessible data. (CVE-2013-3752)

  - Vulnerability in the Solaris component of Oracle and Sun
    Systems Products Suite (subcomponent: Kernel). Supported
    versions that are affected are 10 and 11. Easily
    exploitable vulnerability requiring logon to Operating
    System. Successful attack of this vulnerability can
    result in unauthorized Operating System hang or
    frequently repeatable crash (complete DOS). Note:
    CVE-2013-3799 occurs only when Solaris is running on
    AMD64 platform. (CVE-2013-3799)"
  );
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/1841215.xml
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ea2e3d44"
  );
  # http://www.oracle.com/technetwork/topics/security/cpujuly2013-1899826.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d601a70e"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.oracle.com/rs?type=doc&id=1547593.1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the july2013 CPU from the Oracle support website."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/11");
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


fix_release = "0.5.11-0.175.1.0.0.0.0";

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.0.0.0.0", sru:"11.1.0.0.0") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report2());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
