#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for jan2015.
#
include("compat.inc");

if (description)
{
  script_id(80942);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/11/13 15:27:58 $");

  script_cve_id("CVE-2015-0428");
  script_bugtraq_id(72144);
  script_osvdb_id(3873, 4030, 13619, 76079, 90007, 93040, 101597, 107729, 113251, 117309, 117310, 117311, 117312, 117313, 117314, 117315, 117316, 117317, 117318, 117319, 117320, 117321, 117322, 117323, 117324, 117325, 117326, 117327);

  script_name(english:"Oracle Solaris Critical Patch Update : jan2015_SRU9_5");
  script_summary(english:"Check for the jan2015 CPU");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch from CPU
jan2015."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This Solaris system is missing necessary patches to address a critical
security update :

  - Vulnerability in the Solaris component of Oracle Sun
    Systems Products Suite (subcomponent: Resource Control).
    Supported versions that are affected are 10 and 11.
    Easily exploitable vulnerability requiring logon to
    Operating System. Successful attack of this
    vulnerability can result in unauthorized Operating
    System hang or frequently repeatable crash (complete
    DOS). (CVE-2015-0428)"
  );
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/2367957.xml
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a18ed6f3"
  );
  # http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c02f1515"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.oracle.com/rs?type=doc&id=1956176.1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the jan2015 CPU from the Oracle support website."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/02/09");
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


fix_release = "0.5.11-0.175.0.9.0.5.0";

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.0.9.0.5.0", sru:"SRU9.5") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report2());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
