#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for oct2013.
#
include("compat.inc");

if (description)
{
  script_id(76836);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/11/13 15:27:58 $");

  script_cve_id("CVE-2013-5862");
  script_bugtraq_id(63072);
  script_osvdb_id(95909, 98497, 98498, 98499, 98500, 98501, 98502, 98503, 98504, 98505, 98506, 98507);

  script_name(english:"Oracle Solaris Critical Patch Update : oct2013_SRU11_1_9_5_1");
  script_summary(english:"Check for the oct2013 CPU");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch from CPU
oct2013."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This Solaris system is missing necessary patches to address a critical
security update :

  - Vulnerability in the Solaris component of Oracle and Sun
    Systems Products Suite (subcomponent: CPU performance
    counters (CPC) drivers). Supported versions that are
    affected are 10 and 11.1. Easily exploitable
    vulnerability requiring logon to Operating System.
    Successful attack of this vulnerability can result in
    unauthorized Operating System hang or frequently
    repeatable crash (complete DOS). (CVE-2013-5862)"
  );
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/1865183.xml
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2ade2909"
  );
  # http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ac29c174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.oracle.com/rs?type=doc&id=1586053.1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the oct2013 CPU from the Oracle support website."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/24");
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


fix_release = "0.5.11-0.175.1.9.0.5.1";

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.9.0.5.1", sru:"11.1.9.5.1") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report2());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
