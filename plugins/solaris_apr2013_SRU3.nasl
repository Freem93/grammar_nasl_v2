#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for apr2013.
#
include("compat.inc");

if (description)
{
  script_id(76803);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/11/13 15:27:57 $");

  script_cve_id("CVE-2013-0405");
  script_bugtraq_id(59157);
  script_osvdb_id(92444, 92445, 92446, 92447, 92448, 92449, 92450, 92451, 92452, 92453, 92454, 92455, 92456, 92457, 92458, 92459);

  script_name(english:"Oracle Solaris Critical Patch Update : apr2013_SRU3");
  script_summary(english:"Check for the apr2013 CPU");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch from CPU
apr2013."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This Solaris system is missing necessary patches to address a critical
security update :

  - Vulnerability in the Solaris component of Oracle and Sun
    Systems Products Suite (subcomponent: Filesystem/NFS).
    Supported versions that are affected are 8, 9, 10 and
    11. Easily exploitable vulnerability allows successful
    unauthenticated network attacks via IPv6. Successful
    attack of this vulnerability can result in unauthorized
    update, insert or delete access to some Solaris
    accessible data as well as read access to a subset of
    Solaris accessible data. Note: CVE-2013-0405 occurs only
    when the Solaris NFS client mounts the NFS server over
    IPv6. (CVE-2013-0405)"
  );
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/1841214.xml
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ebf0beb"
  );
  # http://www.oracle.com/technetwork/topics/security/cpuapr2013-1899555.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?028971b4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.oracle.com/rs?type=doc&id=1526078.1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the apr2013 CPU from the Oracle support website."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/16");
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


fix_release = "0.5.11-0.175.0.3.0.4.0";

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.0.3.0.4.0", sru:"Solaris 11.0.3.4") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report2());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
