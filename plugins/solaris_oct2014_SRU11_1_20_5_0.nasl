#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for oct2014.
#
include("compat.inc");

if (description)
{
  script_id(78463);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/11/13 15:27:58 $");

  script_cve_id("CVE-2014-6508");
  script_bugtraq_id(70549);
  script_osvdb_id(107729, 113352);

  script_name(english:"Oracle Solaris Critical Patch Update : oct2014_SRU11_1_20_5_0");
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
"This Solaris system is missing necessary patches to address a critical
security update :

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: iSCSI Data
    Mover(IDM)). Supported versions that are affected are 10
    and 11. Easily exploitable vulnerability allows
    successful unauthenticated network attacks via TCP/IP.
    Successful attack of this vulnerability can result in
    unauthorized Operating System hang or frequently
    repeatable crash (complete DOS). (CVE-2014-6508)"
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
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");

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


fix_release = "0.5.11-0.175.1.20.0.5.0";

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.20.0.5.0", sru:"S11.1.20.5.0") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report2());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
